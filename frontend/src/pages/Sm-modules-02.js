import {useState,useEffect,useRef} from 'react';
import { useSearchParams } from 'react-router-dom';

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
        Input,
        Modal,
        Badge,
        TokenGroup,
        Alert,
        Select
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import { createLabelFunction, customFormatNumberShort } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";



//--## Main function
function Application() {

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
    const [navigationOpen, setNavigationOpen] = useState(false);

    //-- Get Parameters
    const [params]=useSearchParams();
    const moduleId=params.get("mtid");

    //-- Table columns Resources
    const columnsTableResources = [
        {id: 'account_id',header: 'Account',cell: item => item['account_id'],ariaLabel: createLabelFunction('account_id'),sortingField: 'account_id',},
        {id: 'region',header: 'Region',cell: item => item['region'],ariaLabel: createLabelFunction('region'),sortingField: 'region',},
        {id: 'service',header: 'Service',cell: item => item['service'],ariaLabel: createLabelFunction('service'),sortingField: 'service',},
        {id: 'resource_type',header: 'Type',cell: item => item['resource_type'],ariaLabel: createLabelFunction('resource_type'),sortingField: 'resource_type',},
        {id: 'resource_id',header: 'Identifier',cell: item => item['resource_id'],ariaLabel: createLabelFunction('resource_id'),sortingField: 'resource_id',},
        {id: 'name',header: 'Name',cell: item => item['name'],ariaLabel: createLabelFunction('name'),sortingField: 'name',},
        {id: 'creation_date',header: 'Creation',cell: item => item['creation_date'],ariaLabel: createLabelFunction('creation_date'),sortingField: 'creation_date',},
        {id: 'tags_number',header: 'Tags',cell: item => (
              <a  href='#;' style={{ "text-decoration" : "none", "color": "inherit" }}  onClick={() => showTags(item) }>
                  <Badge color="blue">{item['tags_number']}</Badge>
              </a>
          )  ,ariaLabel: createLabelFunction('tags_number'),sortingField: 'tags_number',},
        {id: 'arn',header: 'Arn',cell: item => item['arn'],ariaLabel: createLabelFunction('arn'),sortingField: 'arn',},
    ];

    const visibleContentResources = ['account_id', 'region', 'service', 'resource_type', 'resource_id','creation_date', 'name', 'tags_number', 'metadata'];
    const [datasetResources,setDatasetResources] = useState([]);

    //-- Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);

    //-- Table columns Tags
    const columnsTableTags = [
        {id: 'key',header: 'Key',cell: item => item.key,ariaLabel: createLabelFunction('key'),sortingField: 'key', width : "250px"},
        {id: 'value',header: 'Value',cell: item => item.value,ariaLabel: createLabelFunction('value'),sortingField: 'value',},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags,setItemsTableTags] = useState([]);

    //-- Service items
    const [serviceItems, setServiceItems] = useState([]);
    const [processRunning,setProcessRunning] = useState(false);

    //-- Input fields
    var currentAccount = useRef("");
    var currentRegion = useRef("us-east-1");
    const [inputAccount, setInputAccount] = useState("");
    const [selectedRegion, setSelectedRegion] = useState({ label: "us-east-1", value: "us-east-1" });
    const [regionOptions, setRegionOptions] = useState([]);




    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Content-Type","application/json");
        return xhr;
    }




    //--## Validate Module
    async function validateModule(){
      try {

            setProcessRunning(true);
            setDatasetResources([]);
            setServiceItems([]);

            var parameters = {
                            processId : 'modules::api-305-validate-module-content',
                            fileName : moduleId,
                            accountId : currentAccount.current,
                            region : currentRegion.current
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      switch(api.status){

                          case 200:
                                    var response = JSON.parse(api.responseText)?.['response'];
                                    var services = response['services'];
                                    var items = [];
                                    for (var index in services) {
                                        items.push(
                                          {
                                            label: services[index]['service'],
                                            description: services[index]['message'],
                                            iconName: ( services[index]['status'] == "success" ? "status-positive" : "status-negative")
                                          }
                                        );
                                      }
                                      setDatasetResources(JSON.parse(response['resources']));
                                      setServiceItems(items);
                                      setProcessRunning(false);
                                      showMessage({type : "success", content : `Validation process has been completed, review validation results.`});
                                      break;
                            case 500:
                                      var response = JSON.parse(api.responseText);
                                      showMessage({type : "error", content : response['message']});
                                      setProcessRunning(false);

                      }

            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 21-validate-module-content');
      }
    };




    //--## Show tags for specific resource
    async function showTags(item){
      try{
          const jsonArray = Object.entries(item?.['tags']).map(([key, value]) => ({ key, value }));
          setItemsTableTags(jsonArray);
          setVisibleShowTags(true);
      }
      catch(err){
        console.log(err);
      }
    }




    //--## Show messages
    function showMessage(object){
      setApplicationMessage([
            {
              type: object.type,
              content: object.content,
              dismissible: true,
              dismissLabel: "Dismiss message",
              onDismiss: () => setApplicationMessage([]),
              id: "message_1"
            }
      ]);
    }



    //--## Get Region Catalog
    async function getRegionCatalog(){
      try {
            var parameters = {
                            processId : 'profiles::api-205-get-profile-catalog'
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          var regions = [];
                          response['regions'].forEach(element => {
                            regions.push({ label: element, value: element });
                          });
                          setRegionOptions(regions);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 24-get-profile-catalog');
      }
    }



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        getRegionCatalog();
    }, []);



    //--## Rendering
    return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/modules/"} />}
            navigationOpen={navigationOpen}
            onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <ContentLayout
                          defaultPadding
                          header={
                              <Header variant="h1" description="Run discovery checks against AWS resources to verify module accuracy and confirm service type coverage.">
                                  Module Management - Validation ({moduleId})
                              </Header>
                          }
                      >
                          <Flashbar items={applicationMessage} />
                          <br/>
                          {/* ----### Validation Process */}
                          <Container
                                header={
                                  <Header
                                    variant="h2"
                                    description="Configure the target AWS account and region, then run the validation to test resource discovery for each service type."
                                  >
                                    Validation process
                                  </Header>
                                }
                          >
                            <Alert
                                statusIconAriaLabel="Info"
                              >
                                This process will provide a set of checks and tests to confirm that the main discovery code accurately identifies and reports AWS resources across different services.Each service type will be validate and results will be shown. Set the AWS Account ID, Region and Click on Validate to start the process.
                                <br/>
                                <br/>
                                <table style={{"width":"100%"}}>
                                    <tr>
                                        <td valign="middle" style={{"width":"20%", "padding-right": "2em", "text-align": "left"}}>
                                          <FormField
                                              label="Account"
                                            >
                                              <Input
                                                disabled={processRunning}
                                                value={inputAccount}
                                                onChange={event => {
                                                          currentAccount.current=event.detail.value;
                                                          setInputAccount(event.detail.value);
                                                }
                                                }
                                              />
                                          </FormField>
                                        </td>
                                        <td valign="middle" style={{"width":"20%", "padding-right": "2em", "text-align": "left"}}>
                                          <FormField
                                              label="Region"
                                            >
                                              <Select
                                                disabled={processRunning}
                                                selectedOption={selectedRegion}
                                                onChange={({ detail }) => {
                                                    setSelectedRegion(detail.selectedOption);
                                                    currentRegion.current = detail.selectedOption.value;
                                                }}
                                                options={regionOptions}
                                                filteringType="auto"
                                                expandToViewport={true}
                                              />
                                          </FormField>
                                        </td>
                                        <td valign="middle" style={{"width":"15%", "padding-right": "2em", "text-align": "left"}}>
                                            <FormField>
                                                <br/>
                                                <Button
                                                          disabled={processRunning}
                                                          loading={processRunning}
                                                          onClick={() => {
                                                                validateModule();
                                                            }
                                                          }
                                                  >
                                                    Validate
                                                </Button>
                                            </FormField>
                                        </td>
                                        <td valign="middle" style={{"width":"45%", "padding-right": "2em", "text-align": "center"}}>
                                        </td>
                                    </tr>
                                </table>

                            </Alert>
                          </Container>
                          <br/>

                          {/* ----### Validation Results */}
                          <Container
                                    header={
                                      <Header
                                        variant="h2"
                                        description="Service types validated and their discovery status for the selected module."
                                      >
                                        Validation results
                                      </Header>
                                    }
                          >
                              <TokenGroup
                                items={serviceItems}
                              />
                          </Container>
                          <br/>

                          {/* ----### Resources Table */}
                          <Container>
                              <CustomTable01
                                  columnsTable={columnsTableResources}
                                  visibleContent={visibleContentResources}
                                  dataset={datasetResources}
                                  title={"Resources"}
                                  description={""}
                                  pageSize={10}
                                  onSelectionItem={( item ) => {

                                    }
                                  }
                                  extendedTableProperties = {
                                      {
                                          variant : "borderless",
                                          loading : (""=="in-progress" ? true : false )
                                  }
                                  }
                                />
                            </Container>

                      </ContentLayout>

            }
          />


          {/* ----### Tags Modal */}
          <Modal
            onDismiss={() => setVisibleShowTags(false)}
            visible={visibleShowTags}
            size={"large"}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                  <Button variant="primary" onClick={() => setVisibleShowTags(false)} >Close</Button>
                </SpaceBetween>
              </Box>
            }
            header={
                      <Header
                      variant="h1"
                      description={"Tags that are assigned to the resource."}
                    >
                      Resource tags
                    </Header>
            }
          >
            <CustomTable01
                  columnsTable={columnsTableTags}
                  visibleContent={visibleTableTags}
                  dataset={itemsTableTags}
                  title={"Custom tags"}
                  description={""}
                  pageSize={10}
                  onSelectionItem={( item ) => {

                    }
                  }
                  extendedTableProperties = {
                      { variant : "borderless" }
                  }
              />
          </Modal>

    </div>
  );
}

export default Application;
