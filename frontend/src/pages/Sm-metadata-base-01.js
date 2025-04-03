import {useState,useEffect,useRef, useCallback} from 'react'
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";

import {
  AppLayout,
  SideNavigation,
  Flashbar,
  Header,
  Box,  
  ExpandableSection,
  Icon,
  SpaceBetween,
  Button,  
  Select,
  FormField,
  Modal,
  Input,
  TokenGroup,
  Link
} from '@cloudscape-design/components';

import { createLabelFunction, customFormatNumberShort } from '../components/Functions';

//import '@aws-amplify/ui-react/styles.css';

function Application() {


    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);

           
    // Selected scanning process
    var currentScanId = useRef({});
    const [isSelectMetadataBase,setIsSelectMetadataBase] = useState(false);
   

    const columnsTableProcess = [          
          {id: 'scan_id',header: 'Identifier',cell: item => (            
                <Link href={"/metadata/search?mtid=" + item['scan_id']} variant="primary" external>
                  {item['scan_id']}
                </Link>
              )  ,ariaLabel: createLabelFunction('scan_id'),sortingField: 'scan_id',},                                 
          {id: 'name',header: 'Name',cell: item => item.name,ariaLabel: createLabelFunction('name'),sortingField: 'name',},
          {id: 'status',header: 'Status',cell: item => ( 
            <div style={{"text-align" : "center"}}>                                                                                      
                <Icon name={( item['status'] == "completed" ? "status-positive" : ( item['status'] == "in-progress" ? "status-pending" : "status-negative" )  )}  />
                &nbsp; { ( item['status'] == "completed" ? "Available" : ( item['status'] == "in-progress" ? "In-Progress" : "Unknown" ) ) }
            </div> )  ,ariaLabel: createLabelFunction('action'),sortingField: 'action',},                                 
          {id: 'start_time',header: 'Creation time',cell: item => item.start_time,ariaLabel: createLabelFunction('start_time'),sortingField: 'start_time',},
          {id: 'end_time',header: 'Completed time',cell: item => item.end_time,ariaLabel: createLabelFunction('end_time'),sortingField: 'end_time',},          
          {id: 'resources',header: 'Resources',cell: item => customFormatNumberShort(item.resources,0),ariaLabel: createLabelFunction('resources'),sortingField: 'resources',},
          {id: 'message',header: 'Messages',cell: item => item.message,ariaLabel: createLabelFunction('message'),sortingField: 'message',},
    ];
    const visibleTableProcess = ['scan_id', 'name', 'status', 'start_time', 'end_time',  'resources', 'message' ];
    const [itemsTableProcess,setItemsTableProcess] = useState([]);   


  //--## Create Metadatabase Options
  const [selectedAccounts,setSelectedAccounts] = useState([]);
  const [selectedRegions,setSelectedRegions] = useState([]);
  const [selectedServices,setSelectedServices] = useState([]);
  
  const accountList = useRef([]);
  const regionList = useRef([]);
  const serviceList = useRef([]);
  
  const [inputAccounts, setInputAccounts] = useState("");
  const [inputRegions, setInputRegions] = useState("");
  const [inputServices, setInputServices] = useState("");

  
  const [visibleCreateMetadataBase, setVisibleCreateMetadataBase] = useState(false);
  const [visibleDeleteMetadataBase, setVisibleDeleteMetadataBase] = useState(false);

  const [datasetProfiles,setDatasetProfiles] = useState([]);
  const [selectedProfile,setSelectedProfile] = useState([]);
  var currentParameters = useRef({});

  const [metadataBaseName,setMetadataBaseName] = useState("");
  var currentMetadataBaseName = useRef("");

    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
        xhr.setRequestHeader("Content-Type","application/json");            
        return xhr;
    }


    //--## Refresh Parameters
    function refreshParameters(parameters){

          //-- Create option list accounts    
      
          var accounts = [];
          parameters['accounts'].forEach( element => {
            accounts.push({ label: element, value: element });
          });
          setSelectedAccounts(accounts);
          accountList.current = accounts;
      
          
          //-- Create option list regions    
      
          var regions = [];
          parameters['regions'].forEach( element => {
            regions.push({ label: element, value: element });
          });
          setSelectedRegions(regions);
          regionList.current = regions;
      
          
          //-- Create option list services
      
          var services = [];
          parameters['services'].forEach( element => {
            services.push({ label: element, value: element });
          });
          setSelectedServices(services);
          serviceList.current = services;     
          
      
    }

  
    //--## Gather Profiles
    async function gatherProfiles(){
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
                              items.push({ label: element['jsonProfile']['name'], value: element['profileId'], parameters : JSON.stringify(element['jsonProfile'],null,4) });
                          });            
                          
                          
                          if ( items.length > 0 ){

                                currentParameters.current = items[0]['parameters'];
                                refreshParameters(JSON.parse(items[0]['parameters']));
                                setSelectedProfile(items[0]);                      
                          }    
                          setDatasetProfiles(items);                   
                        
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));        
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 12-get-profiles');                  
      }
    };




    //--## Get Metadata Bases
    async function getMetadataBases(){
      try {
          
            var parameters = {                         
                            processId : "13-get-dataset-metadata-bases"           
            };        
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                      
                          setItemsTableProcess(response['processes']);  
                          setIsSelectMetadataBase(false);                                                    
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 13-get-dataset-metadata-bases');                  
      }
    };

    function createMetadataBase(){
          
        var mtBaseName = "metadatase-base-" + Math.random().toString(36).substring(2,12);       
        currentMetadataBaseName.current = mtBaseName;         
        setMetadataBaseName(mtBaseName);
        setVisibleCreateMetadataBase(true);         

    }
    


    //--## Create Metadata Search  
    const handleCreateMetadataSearch = useCallback(() => {      
          try {
          
                var scanId = ((new Date().toISOString().replace("T",".").substring(0, 19)).replaceAll(":","")).replaceAll("-","");
                currentScanId.current['scan_id'] = scanId;

                var ruleset = {};
                ruleset['accounts'] = accountList.current;
                ruleset['regions'] = regionList.current;                
                ruleset['services'] = serviceList.current;               
                ruleset['tags'] = [];
                ruleset['action'] = 0;
                ruleset['filter'] = "";

                var parameters = {                         
                                processId : "02-create-metadata-search", 
                                scanId : scanId,
                                name : currentMetadataBaseName.current,
                                ruleset : ruleset,
                                type : 2                         
                };        
                

                const api = createApiObject({ method : 'POST', async : true });          
                api.onload = function() {                    
                          if (api.status === 200) {    
                              var response = JSON.parse(api.responseText)?.['response'];                                                                    
                              getMetadataBases(); 
                          }
                };
                api.send(JSON.stringify({ parameters : parameters }));   
                
                
          }
          catch(err){
                console.log(err);
                console.log('Timeout API error - PID: 02-create-metadata-search');                  
          }
          
    }, []);


    //--## Delete Metadata Search  
    const handleClickDeleteMetadataBase = useCallback(() => {      
          try {
          
                
                var parameters = {                         
                                processId : "16-delete-metadata-base", 
                                scanId : currentScanId.current['scan_id']                                
                };        
                

                const api = createApiObject({ method : 'POST', async : true });          
                api.onload = function() {                    
                          if (api.status === 200) {    
                              var response = JSON.parse(api.responseText)?.['response'];                                                                          
                              getMetadataBases(); 
                          }
                };
                api.send(JSON.stringify({ parameters : parameters }));   
                
                
          }
          catch(err){
                console.log(err);
                console.log('Timeout API error - PID: 16-delete-metadata-base');                  
          }
      
    }, []);



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherProfiles();
        getMetadataBases();
    }, []);
    
  return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout            
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/metadata/bases/"} />}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <div style={{"padding" : "1em"}}>
                          <Flashbar items={applicationMessage} />                          
                          <Header variant="h1">
                              Metadata Bases
                          </Header>
                          <br/>
                          <ExpandableSection
                            defaultExpanded
                            variant="container"
                            headerText="How it works"
                          >   
                                <table style={{"width":"100%"}}>
                                <tr>  
                                    <td style={{"width":"33%", "padding-right": "2em", "text-align": "left", "vertical-align" : "top" }}>                                          
                                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                          <Icon name={"add-plus"} size="medium" />
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Create a Metadata Base</span>
                                        </div>                          
                                        <br/>                          
                                        <SpaceBetween size="s">
                                          <div>
                                            <strong>Comprehensive AWS Service Coverage:</strong> Build a Metadata Base that captures configuration details across all your AWS services, providing a single source of truth for your infrastructure.
                                          </div>
                                          <div>
                                            <strong>Advanced Querying Capabilities:</strong> Utilize powerful search and filtering options to quickly locate specific configurations across your entire AWS environment.
                                          </div>
                                        </SpaceBetween>
                                        <br/>
                                        <Button
                                              onClick={() => { 
                                                createMetadataBase();
                                              }}
                                        >
                                            Create Metadata Base
                                        </Button>
                                
                                    </td>
                                    <td style={{"width":"33%", "padding-right": "2em", "text-align": "left", "vertical-align" : "top"}}>  
                                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                          <Icon name={"search"} size="medium" />
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Analyze and Optimize</span>
                                        </div>                          
                                        <p>Query your Metadata Base to identify configuration patterns, review against best practices, and uncover potential risks or optimization opportunities across your AWS infrastructure.</p>                                                            
                                    </td>
                                    <td style={{"width":"33%", "padding-right": "2em", "text-align": "left", "vertical-align" : "top"}}>                                      
                                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                          <Icon name={"settings"} size="medium" />
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Enhance AWS Management</span>
                                        </div>                          
                                        <p>Integrate Metadata Base insights into your DevOps workflows, compliance checks, and infrastructure-as-code processes to maintain a well-optimized and secure AWS environment.</p>
                                    </td>
                                </tr>
                            </table>    

                            
                          </ExpandableSection>
                          <br/>                             
                          <CustomTable01
                              columnsTable={columnsTableProcess}
                              visibleContent={visibleTableProcess}
                              dataset={itemsTableProcess}
                              title={"Metadata Bases"}
                              description={""}
                              pageSize={10}
                              onSelectionItem={( item ) => {
                                  currentScanId.current = item[0];  
                                  setIsSelectMetadataBase(true);                                 

                                }
                              }
                              tableActions={
                                              <SpaceBetween
                                                direction="horizontal"
                                                size="xs"
                                              >    
                                                <Button iconName="refresh" 
                                                        onClick={() => { 
                                                              getMetadataBases();
                                                        }}
                                                >
                                                </Button>
                                                <Button 
                                                        disabled={!isSelectMetadataBase}
                                                        onClick={() => { 
                                                          setVisibleDeleteMetadataBase(true);
                                                        }}
                                                >
                                                  Delete
                                                </Button>                                                                                              
                                                <Button external={false}
                                                        disabled={!isSelectMetadataBase}
                                                        iconAlign="right"
                                                        iconName="external"
                                                        target="_blank"
                                                        href={"/metadata/search?mtid=" + currentScanId.current['scan_id']}                                                        
                                                >
                                                  Explore Metadata Base
                                                </Button>  
                                                <Button 
                                                        onClick={() => { 
                                                          createMetadataBase();
                                                        }}
                                                >
                                                  Create
                                                </Button>
                                                
                                              
                                              </SpaceBetween>
                              }
                          />                          
                          
                  </div>
                
            }
          />
       
          
          <Modal
                onDismiss={() => setVisibleCreateMetadataBase(false)}
                visible={visibleCreateMetadataBase}
                size={"max"}
                footer={
                  <Box float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                      <Button variant="primary" onClick={() => setVisibleCreateMetadataBase(false)} >Cancel</Button>
                      <Button 
                          variant="primary" 
                          onClick={() =>  {
                                    accountList.current =  selectedAccounts.map(obj => obj.value);
                                    regionList.current =  selectedRegions.map(obj => obj.value);
                                    serviceList.current =  selectedServices.map(obj => obj.value);                                                                                                                                                      
                                    handleCreateMetadataSearch();
                                    setVisibleCreateMetadataBase(false);
                                  }
                          } 
                      >
                        Create
                      </Button>
                      
                    </SpaceBetween>

                  </Box>
                }
                header={
                          <Header
                          variant="h1"
                          description={"Define Metadata Base definition."}
                        >
                          Create Metadata Base
                        </Header>
                }            
              >            
                 
                  <table style={{"width":"100%"}}>
                    <tr>  
                        <td valign="middle" style={{"width":"25%", "padding-right": "2em", "text-align": "center"}}> 
                        <FormField
                            label="Name"
                            description="Provide the name for the metadata base."
                          >
                            <Input 
                                value={metadataBaseName}
                                onChange={({ detail }) => {
                                    setMetadataBaseName(detail.value);
                                    metadataBaseName.current = detail.value;
                                }
                              }
                            />
                          </FormField> 
                          <br/> 
                          <FormField label={"Profiles"} description="Select the configuration profile.">
                              <Select
                                        selectedOption={selectedProfile}
                                        onChange={({ detail }) => {
                                          setSelectedProfile(detail.selectedOption);
                                          currentParameters.current = detail.selectedOption['parameters'];    
                                          refreshParameters(JSON.parse(detail.selectedOption['parameters']));                                                                                                                                                          
                                        }}
                                        options={datasetProfiles}
                              />
                          </FormField>
                        </td>
                        <td valign="middle" style={{"width":"15%", "padding-right": "2em", "text-align": "center"}}>  
                          
                        </td>                                        
                    </tr>
                  </table>  
                  <br/>  
                  <FormField label={"Accounts"} description="Set the AWS accounts used as source for metadata base.">
                      <Input
                        onChange={({ detail }) => {
                                  
                                    setInputAccounts(detail.value);                                                                  
                                  }
                        }
                        value={inputAccounts}
                        onKeyDown={({ detail }) => {
                          if (detail.keyCode == 13){
                                var newItems = [];
                                var listValues = inputAccounts.split(",");
                                for (var i = 0; i < listValues.length; i++) {
                                    if (listValues[i].trim() != "") {
                                      newItems.push({ label : listValues[i].trim(), value : listValues[i].trim() });
                                    }
                                }
                                setSelectedAccounts([...selectedAccounts,...newItems]);                                
                                setInputAccounts("");                                                                                                                         
                          }                                                       
                        }
                      }
                      />
                      <TokenGroup
                        onDismiss={({ detail: { itemIndex } }) => {
                          setSelectedAccounts([
                            ...selectedAccounts.slice(0, itemIndex),
                            ...selectedAccounts.slice(itemIndex + 1)
                          ]);
                        }}
                        items={selectedAccounts}
                        limit={10}
                      />
                  </FormField>
                  <br/>
                  <FormField label={"Regions"} description="Set the AWS regions in scope for the metadata base.">                                                  
                      <Input
                        onChange={({ detail }) => setInputRegions(detail.value)}
                        value={inputRegions}
                        onKeyDown={({ detail }) => {
                          if (detail.keyCode == 13){
                                var newItems = [];
                                var listValues = inputRegions.split(",");
                                for (var i = 0; i < listValues.length; i++) {
                                    if (listValues[i].trim() != "") {
                                      newItems.push({ label : listValues[i].trim(), value : listValues[i].trim() });
                                    }
                                }
                                setSelectedRegions([...selectedRegions, ...newItems]);
                                setInputRegions("");
                          }                                                       
                        }
                      }
                      />
                      <TokenGroup
                        onDismiss={({ detail: { itemIndex } }) => {
                          setSelectedRegions([
                            ...selectedRegions.slice(0, itemIndex),
                            ...selectedRegions.slice(itemIndex + 1)
                          ]);
                        }}
                        items={selectedRegions}
                        limit={10}
                      />
                  </FormField>                                        
                  <br/>                  
                  <FormField label={"Services"} description="Set the AWS services in scope for the metadata base.">                                                  
                      <Input
                        onChange={({ detail }) => setInputServices(detail.value)}
                        value={inputServices}
                        onKeyDown={({ detail }) => {
                          if (detail.keyCode == 13){
                                var newItems = [];
                                var listValues = inputServices.split(",");
                                for (var i = 0; i < listValues.length; i++) {
                                    if (listValues[i].trim() != "") {
                                      newItems.push({ label : listValues[i].trim(), value : listValues[i].trim() });
                                    }
                                }
                                setSelectedServices([...selectedServices, ...newItems]);
                                setInputServices("");
                          }                                                       
                        }
                      }
                      />
                      <TokenGroup
                        onDismiss={({ detail: { itemIndex } }) => {
                          setSelectedServices([
                            ...selectedServices.slice(0, itemIndex),
                            ...selectedServices.slice(itemIndex + 1)
                          ]);
                        }}
                        items={selectedServices}
                        limit={10}
                      />
                  </FormField>
            </Modal>

            <Modal
            onDismiss={() => setVisibleDeleteMetadataBase(false)}
            visible={visibleDeleteMetadataBase}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="link"  
                              onClick={() => { 
                                setVisibleDeleteMetadataBase(false);
                                    }}
                      >
                          Cancel
                      </Button>
                      <Button variant="primary" 
                          onClick={() => {                                          
                                          handleClickDeleteMetadataBase();
                                          setVisibleDeleteMetadataBase(false);
                                      }}
                      >
                        Delete
                      </Button>
                </SpaceBetween>
              </Box>
            }
            header="Delete metadata base"
          >
            Do you want to metadata base  <b>[{currentScanId.current['name']}]</b> ?
          </Modal>
          
    </div>
  );
}

export default Application;
