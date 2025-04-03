import {useState,useEffect,useRef} from 'react'
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';

import {
AppLayout,
SideNavigation,
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
ButtonDropdown
} from '@cloudscape-design/components';

import '@aws-amplify/ui-react/styles.css';

import CodeEditor01  from '../components/CodeEditor01';
import CustomHeader from "../components/Header";

function Application() {

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
   
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


    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
        xhr.setRequestHeader("Content-Type","application/json");            
        return xhr;
    }


    
    //--## Gather Profiles
    async function gatherProfiles(profileSelected){
      try {
            
            var parameters = {                         
                            processId : "12-get-profiles"
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
                              }
                              else{
                                currentProfileId.current = selectedItem['value'];
                                currentProfileName.current = selectedItem['name'];
                                currentJSONProfile.current = JSON.stringify(selectedItem['jsonProfile'],null,4);
                                setSelectedProfile(selectedItem);
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
                            processId : "09-create-profile",
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
                            processId : "10-update-profile",
                            profileId : currentProfileId.current,
                            jsonProfile : JSON.parse(currentJSONProfile.current)
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
                            processId : "11-delete-profile",
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

  
    function findElementByLabel(arr, searchLabel) {
      return arr.find(element => element.label === searchLabel) || null;
    }

    
    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherProfiles(null);
    }, []);
    
    
  return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout            
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/profiles/"} />}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <div style={{"padding" : "1em"}}>
                          <Flashbar items={applicationMessage} />
                          <br/>
                          <Header variant="h1" description="Manage profiles used by tagging and search process.">
                              Profile Management  
                          </Header>
                          <br/>
                          <Container>
                            <table style={{"width":"100%"}}>
                                <tr>  
                                    <td valign="middle" style={{"width":"35%", "padding-right": "2em", "text-align": "center"}}>  
                                      <FormField label={"Profile"}>
                                          <Select
                                                    disabled={visibleEditProfile}
                                                    selectedOption={selectedProfile}
                                                    onChange={({ detail }) => {
                                                      currentJSONProfile.current = JSON.stringify(detail.selectedOption['jsonProfile'],null,4);
                                                      currentProfileId.current = detail.selectedOption['value'];
                                                      currentProfileName.current = detail.selectedOption['label'];
                                                      setSelectedProfile(detail.selectedOption);                                                                                                         
                                                    }}
                                                    options={profileDataset}
                                          />
                                      </FormField>
                                    </td>
                                    <td valign="middle" style={{"width":"30%", "padding-right": "2em", "text-align": "center"}}>  
                                          
                                    </td>
                                    <td valign="middle" style={{"width":"35%", "padding-right": "2em", "text-align": "center"}}>  
                                            <Box float="right">
                                              <SpaceBetween direction="horizontal" size="xs">
                                                
                                              <Button 
                                                    iconName="refresh" 
                                                    disabled={visibleEditProfile}
                                                    onClick={() => { 
                                                      gatherProfiles();
                                                    }}>

                                                </Button>
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
                                                            break;
                                                          
                                                          case "delete":
                                                            setVisibleDeleteProfile(true);
                                                            break;

                                                      }
                                                        
                                                    }
                                                  }
                                                >
                                                  Action
                                                </ButtonDropdown>
                                                                                         
                                                
                                              </SpaceBetween>

                                            </Box>
                                    </td>
                                </tr>
                            </table>                                 
                                    
                            <table style={{"width":"100%"}}>
                                <tr>  
                                    <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>  
                                            
                                            <CodeEditor01
                                              format={"json"}
                                              value={currentJSONProfile.current}
                                              readOnly={!visibleEditProfile}
                                              header={
                                                        <Header
                                                          variant="h4"
                                                        >
                                                          Profile editor
                                                        </Header>
                                                      }
                                                onChange={ ( item ) => { currentJSONProfile.current = item; } }
                                            />
                                                  { visibleEditProfile &&
                                                  <div>
                                                      <br/>
                                                      <Box float="right">
                                                        <SpaceBetween direction="horizontal" size="xs">
                                                            <Button variant="link"  
                                                                      onClick={() => { 
                                                                        setVisibleEditProfile(false);
                                                                        gatherProfiles(currentProfileName.current);
                                                                        }}
                                                              >
                                                                  Cancel
                                                              </Button>
                                                              <Button variant="primary" 
                                                                  onClick={() => {                                          
                                                                                  handleClickUpdateProfile();            
                                                                                  setVisibleEditProfile(false);                                                                  
                                                                              }}
                                                              >
                                                                Save
                                                              </Button>
                                                        </SpaceBetween>
                                                      </Box>
                                                  </div>

                                                  }
                                                

                                      </td>
                                </tr>
                                
                            </table>
                          </Container>
                          
                  </div>
                
            }
          />
        
          <Modal
            onDismiss={() => setVisibleCreateProfile(false)}
            visible={visibleCreateProfile}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                  <Button variant="link"  
                          onClick={() => { 
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
            Do you want to delete profile [{currentProfileName.current}] ?
          </Modal>
        
    </div>
  );
}

export default Application;
