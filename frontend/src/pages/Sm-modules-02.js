import {useState,useEffect,useRef} from 'react';
import { useSearchParams } from 'react-router-dom';
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
Input,
Modal,
Badge,
TokenGroup,
Alert
} from '@cloudscape-design/components';

import '@aws-amplify/ui-react/styles.css';

import { createLabelFunction, customFormatNumberShort } from '../components/Functions';
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";

function Application() {

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
   
 
    //-- Get Parameters
    const [params]=useSearchParams();   
    const moduleId=params.get("mtid");  
  

    //-- Table
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

    // Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);

    const columnsTableTags = [
      {id: 'key',header: 'Key',cell: item => item.key,ariaLabel: createLabelFunction('key'),sortingField: 'key', width : "250px"},
      {id: 'value',header: 'Value',cell: item => item.value,ariaLabel: createLabelFunction('value'),sortingField: 'value',},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags,setItemsTableTags] = useState([]);

    const [serviceItems, setServiceItems] = useState([]);
    const [processRunning,setProcessRunning] = useState(false);

    var currentAccount = useRef("");
    var currentRegion = useRef("");
    const [inputAccount, setInputAccount] = useState("");
    const [inputRegion, setInputRegion] = useState("");
    

    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
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
                            processId : "21-validate-module-content",
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


    //--## Show tags for especifig resource
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


    
    
  return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout            
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/modules/"} />}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <div style={{"padding" : "1em"}}>
                          <Flashbar items={applicationMessage} />
                          <br/>
                          <Header variant="h1" description="Validate and verify module functionality.">
                              Module Management - Validation ({moduleId})  
                          </Header>
                          <br/>
                          <Container
                                header={
                                  <Header
                                    variant="h2"                                    
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
                                              <Input
                                                disabled={processRunning}
                                                value={inputRegion}
                                                onChange={event => {
                                                        setInputRegion(event.detail.value)
                                                        currentRegion.current=event.detail.value;
                                                    }
                                                }
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
                          <Container
                                    header={
                                      <Header
                                        variant="h2"                                    
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
                          
                  </div>
                
            }
          />
        
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
