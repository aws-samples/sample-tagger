import {useState,useEffect,useRef, useCallback} from 'react'

//--## CloudScape components
import {
        AppLayout,
        SideNavigation,
        ContentLayout,
        Flashbar,
        SpaceBetween,
        Button,
        Header,
        Box,
        Container,
        FormField,
        Select,
        Input,
        Modal,
        ButtonDropdown,
        Multiselect
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';


//--## Custom components
import CustomHeader from "../components/Header";
import WhereClauseBuilder01 from '../components/WhereClauseBuilder01';
import TokenInput01 from '../components/TokenInput01';
import TokenGroupReadOnly01 from '../components/TokenGroupReadOnly01';
import TokenMultiSelect01 from '../components/TokenMultiSelect01';
import TagEditorComponent from '../components/TagEditor-01';
import RegionEditorComponent from '../components/RegionEditor-01';
import ServiceEditorComponent from '../components/ServiceEditor-01';
import AccountEditorComponent from '../components/AccountEditor-01';



//--## Main function
function Application() {

    //-- Token items
    const [items, setItems] = useState([
        { label: "Item 1", dismissLabel: "Remove item 1" },
        { label: "Item 2", dismissLabel: "Remove item 2" },
        { label: "Item 3", dismissLabel: "Remove item 3" }
    ]);

    //-- Where Clause
    const [sqlWhereClause, setSqlWhereClause] = useState('');
    const [isReadOnly, setIsReadOnly] = useState(true);

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
    const [navigationOpen, setNavigationOpen] = useState(false);

    //-- Profiles
    const [profileName, setProfileName] = useState("");
    var currentProfileName = useRef("");
    var currentProfileId = useRef("");
    var currentJSONProfile = useRef("{}");

    const [selectedProfile,setSelectedProfile] = useState({});
    const [profileDataset,setProfileDataset] = useState([]);

    const [visibleCreateProfile, setVisibleCreateProfile] = useState(false);
    const [visibleDeleteProfile, setVisibleDeleteProfile] = useState(false);
    const [visibleEditProfile, setVisibleEditProfile] = useState(false);

    const [templateJson,setTemplateJson] = useState({
          name: "",
          description: "",
          accounts: [],
          regions: [],
          services: [],
          filter: "",
          tags: [],
          action: ""
    });
    var templateJsonCurrent = useRef({});

    const [profileCatalogs, setProfileCatalogs] = useState({ regions : [], services : [] });




    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Content-Type","application/json");
        return xhr;
    }




    //--## Handle WhereClause change
    const handleWhereClauseChange = useCallback((newValue) => {
      setSqlWhereClause(newValue);
      templateJsonCurrent.current['filter'] = newValue;
    }, []);




    //--## Gather Profiles
    async function gatherProfiles(profileSelected){
      try {

            var parameters = {
                            processId : 'profiles::api-204-get-profiles'
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {

                          var response = JSON.parse(api.responseText)?.['response'];

                          const profiles = response.sort((a, b) =>
                              a.jsonProfile.name.localeCompare(b.jsonProfile.name)
                          );

                          var items = [];
                          profiles.forEach(element => {
                              items.push({ label: element['jsonProfile']['name'], value: element['profileId'], jsonProfile : element['jsonProfile'] });
                          });


                          var selectedItem = findElementByLabel(items, profileSelected);

                          if ( items.length > 0 ){

                              if (selectedItem == null){

                                currentProfileId.current = items[0]['value'];
                                currentProfileName.current = items[0]['label'];
                                currentJSONProfile.current = JSON.stringify(items[0]['jsonProfile'],null,4);
                                setSelectedProfile(items[0]);
                                setSqlWhereClause(items[0]['jsonProfile']['filter']);
                                templateJsonCurrent.current = items[0]['jsonProfile'];
                                setTemplateJson(items[0]['jsonProfile']);

                              }
                              else{
                                currentProfileId.current = selectedItem['value'];
                                currentProfileName.current = selectedItem['label'];
                                currentJSONProfile.current = JSON.stringify(selectedItem['jsonProfile'],null,4);
                                setSelectedProfile(selectedItem);
                                setSqlWhereClause(selectedItem['jsonProfile']['filter']);
                                templateJsonCurrent.current = selectedItem['jsonProfile'];
                                setTemplateJson(selectedItem['jsonProfile']);

                              }
                          }

                          setProfileDataset(items);

                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 20-gather-profiles');
      }
    };




    //--## Create Profile
    async function handleClickCreateProfile(){
      try {

            var profileId = ((new Date().toISOString().replace("T",".").substring(0, 19)).replaceAll(":","")).replaceAll("-","");
            var parameters = {
                            processId : 'profiles::api-201-create-profile',
                            profileId : profileId,
                            jsonProfile : {
                                              name : currentProfileName.current,
                                              description : "Describe the profile usage.",
                                              accounts : ["1234567890","0987654321"],
                                              regions : ['All'],
                                              services : ['All'],
                                              filter : "",
                                              tags : [
                                                        {
                                                            "key" : "mytag1",
                                                            "value" : "myvalue1"
                                                        }
                                              ],
                                              action : "add"
                            }
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = async function() {
                      if (api.status === 200) {

                        var response = JSON.parse(api.responseText)?.['response'];
                        currentProfileId.current = profileId;
                        await gatherProfiles(currentProfileName.current);

                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 21-create-profile');
      }
    };




    //--## Update Profile
    async function handleClickUpdateProfile(){
      try {

            var parameters = {
                            processId : 'profiles::api-202-update-profile',
                            profileId : currentProfileId.current,
                            jsonProfile : templateJsonCurrent.current
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = async function() {
                      if (api.status === 200) {

                          var response = JSON.parse(api.responseText)?.['response'];
                          await gatherProfiles(response['jsonProfile']?.['name']);

                          setApplicationMessage([
                                                  {
                                                    type: "success",
                                                    content: "Profile has been updated successfully.",
                                                    dismissible: true,
                                                    dismissLabel: "Dismiss message",
                                                    onDismiss: () => setApplicationMessage([]),
                                                    id: "message_1"
                                                  }
                          ]);

                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 22-update-profile');
      }
    };



    //--## Delete Profile
    async function handleClickDeleteProfile(){
      try {

            var parameters = {
                            processId : 'profiles::api-203-delete-profile',
                            profileId : currentProfileId.current,
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = async function() {
                      if (api.status === 200) {
                        await gatherProfiles(null);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 11-delete-profile');
      }
    };




    //--## Get Profile catalogs
    async function getProfileCatalogs(){
      try {

            var parameters = {
                            processId : 'profiles::api-205-get-profile-catalog'
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = async function() {
                      if (api.status === 200) {

                          var response = JSON.parse(api.responseText)?.['response'];
                          console.log(response);

                          var regions = [];
                          response['regions'].forEach(element => {
                            regions.push({ label: element , value: element });
                          });

                          var services = [];
                          response['services'].forEach(element => {
                            services.push({ label: element , value: element });
                          });

                          setProfileCatalogs({ regions : regions, services : services });

                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 24-get-profile-catalog');
      }
    };




    //--## Find a element by name
    function findElementByLabel(arr, searchLabel) {
      return arr.find(element => element.label === searchLabel) || null;
    }




    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherProfiles(null);
        getProfileCatalogs();
    }, []);



    //--## Rendering
    return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/profiles/"} />}
            navigationOpen={navigationOpen}
            onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <ContentLayout
                          defaultPadding
                          header={
                              <Header variant="h1" description="Create, edit, and manage discovery profiles that define the scope for resource tagging and compliance operations across your AWS environment.">
                                  Profile Management
                              </Header>
                          }
                      >
                          <Flashbar items={applicationMessage} />

                                    {/* ----### Profile Selection */}
                                    <table style={{"width":"100%"}}>
                                        <tr>
                                            <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>
                                              <FormField label={"Profile"}>
                                                  <SpaceBetween direction="horizontal" size="xs">
                                                      <div style={{minWidth: '350px'}}>
                                                          <Select
                                                                    disabled={visibleEditProfile}
                                                                    selectedOption={selectedProfile}
                                                                    onChange={({ detail }) => {
                                                                      setSelectedProfile(detail.selectedOption);
                                                                      currentProfileId.current = detail.selectedOption['value'];
                                                                      currentProfileName.current = detail.selectedOption['label'];
                                                                      templateJsonCurrent.current = detail.selectedOption['jsonProfile'];
                                                                      setTemplateJson(detail.selectedOption['jsonProfile']);
                                                                      setSqlWhereClause(detail.selectedOption['jsonProfile']['filter']);
                                                                    }}
                                                                    options={profileDataset}
                                                          />
                                                      </div>                                                      
                                                      <ButtonDropdown
                                                          disabled={visibleEditProfile}
                                                          variant={"primary"}
                                                          items={[
                                                            { text: "Create", id: "create"},
                                                            { text: "Edit", id: "edit"},
                                                            { text: "Delete", id: "delete" }
                                                          ]}
                                                          onItemClick={( item ) => {
                                                              switch(item.detail.id){
                                                                  case "create":
                                                                    setVisibleCreateProfile(true);
                                                                    setProfileName("");
                                                                    break;
                                                                  case "edit":
                                                                    setVisibleEditProfile(true);
                                                                    setIsReadOnly(false);
                                                                    break;
                                                                  case "delete":
                                                                    setVisibleDeleteProfile(true);
                                                                    break;
                                                              }
                                                          }}
                                                      >
                                                          Action
                                                      </ButtonDropdown>
                                                      <Button
                                                          iconName="refresh"
                                                          disabled={visibleEditProfile}
                                                          onClick={() => { gatherProfiles(currentProfileName.current); }}
                                                      />
                                                  </SpaceBetween>
                                              </FormField>
                                            </td>
                                            <td valign="middle" style={{"width":"30%", "padding-right": "2em", "text-align": "center"}}>
                                            </td>
                                            <td valign="middle" style={{"width":"35%", "padding-right": "2em", "text-align": "center"}}>
                                                    { visibleEditProfile &&
                                                        <Box float="right">
                                                            <SpaceBetween direction="horizontal" size="xs">
                                                                <Button variant="link"
                                                                    onClick={() => {
                                                                        setVisibleEditProfile(false);
                                                                        setIsReadOnly(true);
                                                                        gatherProfiles(currentProfileName.current);
                                                                    }}
                                                                >
                                                                    Cancel
                                                                </Button>
                                                                <Button variant="primary"
                                                                    onClick={() => {
                                                                        handleClickUpdateProfile();
                                                                        setVisibleEditProfile(false);
                                                                        setIsReadOnly(true);
                                                                    }}
                                                                >
                                                                    Save
                                                                </Button>
                                                            </SpaceBetween>
                                                        </Box>
                                                    }
                                            </td>
                                        </tr>
                                    </table>
                                    <br/>


                              {/* ----### Accounts */}
                              <Container
                                header={
                                        <Header variant="h1" description="AWS account IDs included in the discovery and tagging scope for this profile.">
                                            Accounts
                                        </Header>
                              }
                              >
                                    <AccountEditorComponent
                                        value={templateJson['accounts']}
                                        readOnly={isReadOnly}
                                        onChange={({ detail }) => {
                                            setTemplateJson({...templateJson, accounts: detail.value});
                                            templateJsonCurrent.current['accounts'] = detail.value;
                                        }}
                                    />
                              </Container>
                              <br/>

                              {/* ----### Regions */}
                              <Container
                                header={
                                        <Header variant="h1" description="AWS regions where resource discovery and tagging operations will be performed.">
                                            Regions
                                        </Header>
                              }
                              >
                                    <RegionEditorComponent
                                        value={templateJson['regions']}
                                        readOnly={isReadOnly}
                                        onChange={({ detail }) => {
                                            setTemplateJson({...templateJson, regions: detail.value});
                                            templateJsonCurrent.current['regions'] = detail.value;
                                        }}
                                    />
                              </Container>
                              <br/>

                              {/* ----### Services */}
                              <Container
                                      header={
                                              <Header variant="h1" description="AWS services and resource types targeted for discovery and tagging within this profile.">
                                                  Services
                                              </Header>
                                    }
                                    >
                                    <ServiceEditorComponent
                                        value={templateJson['services']}
                                        readOnly={isReadOnly}
                                        onChange={({ detail }) => {
                                            setTemplateJson({...templateJson, services: detail.value});
                                            templateJsonCurrent.current['services'] = detail.value;
                                        }}
                                    />
                              </Container>
                              <br/>


                              {/* ----### Filter */}
                              <Container
                                    header={
                                            <Header variant="h1" description="Define conditions to narrow down discovered resources based on attributes such as creation date, tags, or resource properties.">
                                                Advanced filtering
                                            </Header>
                                  }
                              >
                                    <WhereClauseBuilder01
                                      onChange={handleWhereClauseChange}
                                      value={sqlWhereClause}
                                      readOnly={isReadOnly}
                                    />

                              </Container>
                              <br/>


                            {/* ----### Tags */}
                            <Container
                                header={
                                        <Header variant="h1" description="Tag key-value pairs to be applied to resources during the tagging process.">
                                            Tags
                                        </Header>
                              }
                              >
                                      <TagEditorComponent
                                          value={templateJson['tags']}
                                          readOnly={isReadOnly}
                                          onChange={({ detail }) => {
                                              setTemplateJson({...templateJson, tags: detail.tags});
                                              templateJsonCurrent.current['tags'] = detail.tags;
                                          }}
                                      />

                              </Container>

                      </ContentLayout>

            }
          />

          {/* ----### Create Profile Modal */}
          <Modal
            onDismiss={() => setVisibleCreateProfile(false)}
            visible={visibleCreateProfile}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                  <Button variant="link"
                          onClick={() => {
                                    setIsReadOnly(true);
                                    setVisibleCreateProfile(false);
                                }}
                  >
                      Cancel
                  </Button>
                  <Button variant="primary"
                      onClick={() => {
                                      currentProfileName.current = profileName;
                                      handleClickCreateProfile();
                                      setVisibleCreateProfile(false);
                                      setIsReadOnly(true);
                                  }}
                  >
                    Create
                  </Button>
                </SpaceBetween>
              </Box>
            }
            header="Create profile"
          >
            <FormField
              label="Name"
              description="Provide the name for the profile."
            >
              <Input
                  value={profileName}
                  onChange={({ detail }) => {
                       setProfileName(detail.value);
                       currentProfileName.current = detail.value;
                  }
                }
              />
            </FormField>
          </Modal>


          {/* ----### Delete Profile Modal */}
          <Modal
            onDismiss={() => setVisibleDeleteProfile(false)}
            visible={visibleDeleteProfile}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="link"
                              onClick={() => {
                                setVisibleDeleteProfile(false);
                                    }}
                      >
                          Cancel
                      </Button>
                      <Button variant="primary"
                          onClick={() => {
                                          handleClickDeleteProfile();
                                          setVisibleDeleteProfile(false);
                                      }}
                      >
                        Delete
                      </Button>
                </SpaceBetween>
              </Box>
            }
            header="Delete profile"
          >
            Do you want to delete profile [{templateJsonCurrent.current['name']}] ?
          </Modal>

    </div>
  );
}

export default Application;
