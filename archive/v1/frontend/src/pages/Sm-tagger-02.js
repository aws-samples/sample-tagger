import {useState,useEffect,useRef, useCallback} from 'react'
import { useNavigate } from "react-router-dom";
import { useSearchParams } from 'react-router-dom';

import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs, tagEditorI18n } from './Configs';
import { createLabelFunction } from '../components/Functions';

import {
AppLayout,
SideNavigation,
Header,
SpaceBetween,
Button,
Modal,
Box,
Flashbar,
Select,
FormField,
Container,
StatusIndicator,
ButtonDropdown,
Input,
TagEditor,
Alert,
Checkbox,
Wizard,
Textarea,
TokenGroup,
Icon,
KeyValuePairs,
Badge,
Link
} from '@cloudscape-design/components';

import CustomHeader from "../components/Header";
import CodeEditor01  from '../components/CodeEditor01';
import CustomTable01 from "../components/Table01";
import CustomTable02 from "../components/Table02";
import TokenGroupReadOnly01 from '../components/TokenGroupReadOnly01';


function Application() {
  
 

  //-- Navigate object
  let navigate = useNavigate(); 
    
  
  //-- Application messages
  const [applicationMessage, setApplicationMessage] = useState([]);

  
  // Table variables Workload
  const columnsTableResources = [
    {id: 'action',header: 'Filtered',cell: item => ( 
      <div style={{"text-align" : "center"}}>                                                                                      
          <Icon name={( item['action'] == "1" ? "status-positive" : ( item['action'] == "2" ? "status-negative" : "status-pending" )  )}  />
          &nbsp; { ( item['action'] == "1" ? "Filter-In" : ( item['action'] == "2" ? "Filter-Out" : "Unknown" ) ) }
      </div> )  ,ariaLabel: createLabelFunction('action'),sortingField: 'action',},      
    {id: 'account',header: 'Account',cell: item => item['account'],ariaLabel: createLabelFunction('account'),sortingField: 'account',},
    //{id: 'account',header: 'Account',cell: item => "1234567890",ariaLabel: createLabelFunction('account'),sortingField: 'account',},
    {id: 'region',header: 'Region',cell: item => item['region'],ariaLabel: createLabelFunction('region'),sortingField: 'region',},
    {id: 'service',header: 'Service',cell: item => item['service'],ariaLabel: createLabelFunction('service'),sortingField: 'service',},
    {id: 'type',header: 'Type',cell: item => item['type'],ariaLabel: createLabelFunction('type'),sortingField: 'type',},    
    {id: 'identifier',header: 'Identifier',cell: item => item['identifier'],ariaLabel: createLabelFunction('identifier'),sortingField: 'identifier',},
    {id: 'name',header: 'Name',cell: item => item['name'],ariaLabel: createLabelFunction('name'),sortingField: 'name',},
    {id: 'creation',header: 'Creation',cell: item => item['creation'],ariaLabel: createLabelFunction('creation'),sortingField: 'creation',},    
    {id: 'tags_number',header: 'Tags',cell: item => (       
          <a  href='#;' style={{ "text-decoration" : "none", "color": "inherit" }}  onClick={() => showTags(item) }>
              <Badge color="blue">{item['tags_number']}</Badge>
          </a>                                                                                        
      )  ,ariaLabel: createLabelFunction('tags_number'),sortingField: 'tags_number',},      
      {id: 'metadata',header: 'Metadata',cell: item => (       
        <a href='#;' style={{ "text-decoration" : "none", "color": "inherit" }}  onClick={() => showMetadata(item) }>
            <Badge color="green">JSON</Badge>
        </a>                                                                                        
    )  ,ariaLabel: createLabelFunction('metadata'),sortingField: 'metadata',},      
    
];

const visibleContentResources = ['action', 'account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];
const [datasetResources,setDatasetResources] = useState([]);

//-- Pagging    
const pageId = useRef(0);
var totalPages = useRef(1);
var totalRecords = useRef(0);
var pageSize = useRef(20);


var txtRuleset = useRef("");

const [selectedRuleSet,setSelectedRuleSet] = useState({});
const [datasetRuleSet,setDatasetRuleSet] = useState([]);       

//--## Get Parameters
const [params]=useSearchParams();   
var currentScanId = useRef(params.get("mtid"));

//--## Tasks
const timeoutRef = useRef(null);

// Scan process
const [searchStatus, setSearchStatus] = useState('idle');
const [searchSummary, setSearchSummary] = useState({ action : 0 });
const [taggingStatus, setTaggingStatus] = useState('idle');

// Selected options filters
const [selectedAccounts,setSelectedAccounts] = useState([]);
const [selectedRegions,setSelectedRegions] = useState([]);
const [selectedServices,setSelectedServices] = useState([]);
const [selectedTags,setSelectedTags] = useState([]);
const accountList = useRef([]);
const regionList = useRef([]);
const serviceList = useRef([]);
const tagList = useRef([]);

const [inputAccounts, setInputAccounts] = useState("");
const [inputRegions, setInputRegions] = useState("");
const [inputServices, setInputServices] = useState("");

const [selectedAction,setSelectedAction] = useState({ label: "Add tags", value: 1 });
const actionTags = useRef(1);

// Filter
const [selectedFilter,setSelectedFilter] = useState("");
const filterList = useRef("");


//-- Start tagging process
const [checkedKnowledge, setCheckedKnowledge] = useState(false);
var taggingState = useRef("Not-Started");

// Filter Action
const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Filter-In', value : "1" });
const filterAction = useRef("1");


// Update actions
const resourceId = useRef({});
const actionType = useRef("0");


// Modal Tags
const [visibleShowTags, setVisibleShowTags] = useState(false);

const columnsTableTags = [
  {id: 'key',header: 'Key',cell: item => item.key,ariaLabel: createLabelFunction('key'),sortingField: 'key', width : "250px"},
  {id: 'value',header: 'Value',cell: item => item.value,ariaLabel: createLabelFunction('value'),sortingField: 'value',},
];
const visibleTableTags = ['key', 'value'];
const [itemsTableTags,setItemsTableTags] = useState([]);


// Modal Metadata
const [visibleShowMetadata, setVisibleShowMetadata] = useState(false);
const [metadata,setMetadata] = useState("");


// Wizard variables
const [activeStepIndex,setActiveStepIndex] = useState(0);
var currentStep = useRef(0);


// Tag errors
const [datasetTagErrors, setDatasetTagErrors] = useState([]);
const [visibleTaggingErrors, setVisibleTaggingErrors] = useState(false);



//--## Show tags for especifig resource
async function showTags(item){        
  try{    
      
      const jsonArray = Object.entries(JSON.parse(item?.['tags_list'])).map(([key, value]) => ({ key, value }));      
      setItemsTableTags(jsonArray);      
      setVisibleShowTags(true);
      
  }
  catch(err){
    console.log(err);                  
  }
}


//--## Show Metadata
async function showMetadata(item){
  try {
       
        var parameters = {                         
                        processId : "07-get-resource-metadata", 
                        scanId : item['scan_id'],
                        seq : item['seq'],
        };                
        
        const api = createApiObject({ method : 'POST', async : true });          
        api.onload = function() {                    
                  if (api.status === 200) {    
                      var response = JSON.parse(api.responseText)?.['response'];                                            
                      setMetadata(JSON.stringify(JSON.parse(response['metadata']),null,4));                          
                      setVisibleShowMetadata(true);                    
                  }
        };
        api.send(JSON.stringify({ parameters : parameters }));            
        
  }
  catch(err){
        console.log(err);
        console.log('Timeout API error - PID: 07-get-resource-metadata');                  
  }
};




//--## Create API object
function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
        xhr.setRequestHeader("Content-Type","application/json");            
        return xhr;
}




//--## Gather Profiles
async function gatherMetadataInformation(){
  try {
        
        var parameters = {                         
                        processId : "15-get-dataset-metadata-information",
                        scanId : currentScanId.current
        };        

        const api = createApiObject({ method : 'POST', async : true });          
        api.onload = function() {                    
                  if (api.status === 200) {    
                      var response = JSON.parse(api.responseText)?.['response'];                                                                               
                      var parameters = JSON.parse(response['processes']['parameters']);                                                  
                      refreshParameters(parameters);          

                  }
        };
        api.send(JSON.stringify({ parameters : parameters }));  


   
        
  }
  catch(err){
        console.log(err);
        console.log('Timeout API error - PID: 15-get-dataset-metadata-information');                  
  }
};




//--## Refresh Discovery parameters
function refreshParameters(parameters){

        //-- Create tag list
        var tags = [];
        parameters['tags'].forEach( element => {
          tags.push({ key: element['key'], value: element['value'] });
        });
        setSelectedTags(tags);
        tagList.current = tags;
       
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



//--## Get task information
async function getScanResults(){
      try {
           
            var parameters = {                         
                            processId : "01-get-metadata-results", 
                            scanId : currentScanId.current,
                            ruleset : txtRuleset.current,
                            action : filterAction.current,
                            page : pageId.current,
                            limit : pageSize.current                     
            };        
            
            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response']; 
                          totalPages.current =   response['pages'];            
                          totalRecords.current =   response['records'];                     
                          setDatasetResources(response['resources']);                          
                          
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 03-get-task-information');                  
      }
};



//--## Get tagging errors 
async function getTaggingErrors(){
  try {
       
        var parameters = {                         
                        processId : "23-get-tagging-errors", 
                        scanId : currentScanId.current,                       
        };        
        

        const api = createApiObject({ method : 'POST', async : true });          
        api.onload = function() {                    
                  if (api.status === 200) {    
                      var response = JSON.parse(api.responseText)?.['response'];                                  
                      setDatasetTagErrors(response['resources']);  
                      setVisibleTaggingErrors(true);                        


                  }
        };
        api.send(JSON.stringify({ parameters : parameters }));            
        
  }
  catch(err){
        console.log(err);
        console.log('Timeout API error - PID: 23-get-tagging-errors');                  
  }
};


//--## Update resource action
async function updateResourceAction(){
  try {
       
                
        var parameters = {                         
                        processId : "04-update-resource-action", 
                        scanId : resourceId.current['scan_id'],
                        seq : resourceId.current['seq'],
                        action : actionType.current                        
        };       
        
        const api = createApiObject({ method : 'POST', async : true });          
        api.onload = function() {                    
                  if (api.status === 200) {    
                      var response = JSON.parse(api.responseText)?.['response'];                                            
                      getScanResults();
                  }
        };
        api.send(JSON.stringify({ parameters : parameters }));            
        
  }
  catch(err){
        console.log(err);
        console.log('Timeout API error - PID: 02-create-metadata-search');                  
  }
};



//--## Get tagging status
const getTaggingProcessStatus = useCallback(async () => {      
  
  try {
      
      var parameters = {                         
                      processId : "06-get-tagging-process-status", 
                      scanId : currentScanId.current
      };        
      
      const api = createApiObject({ method : 'POST', async : true });          
      api.onload = function() {                    
                if (api.status === 200) {    
                    var response = JSON.parse(api.responseText)?.['response']; 
                    var message = JSON.parse(response['message']);                     
                    if (response['status'] === 'completed') {
                        setTaggingStatus('completed');   
                        if (( message['error'] || 0) == 0 ){
                          showMessage({ type : "success", content : `Tagging process ${currentScanId.current} has been completed. Success (${message['success'] || 0 }), Errors (${message['error'] || 0 }).` });                        
                        }
                        else{
                          showMessage({ 
                                        type : "error", 
                                        content : (
                                          <>
                                              Tagging process {currentScanId.current} has been completed. Success ({message['success'] || 0 }), Errors ({message['error'] || 0 }). 
                                              <Link 
                                                    color="inverted" 
                                                    onFollow={() => {
                                                            getTaggingErrors();
                                                    }}               

                                                >
                                                View errors.
                                              </Link>
                                          </>
                                        )
                          });                        
                          /*
                          setApplicationMessage([
                                {
                                  type: object.type,
                                  content: object.content,
                                  dismissible: true,
                                  dismissLabel: "Dismiss message",
                                  onDismiss: () => setApplicationMessage([]),
                                  id: "message_1"
                                }
                          ]);*/
                          
                        }
                        
                    } else if (response['status'] === 'failed') {
                        setTaggingStatus('failed');
                    } else {                      
                      timeoutRef.current = setTimeout(getTaggingProcessStatus, 5000); 
                    }                                           
                    
                }
      };
      api.send(JSON.stringify({ parameters : parameters })); 

  } catch (err) {
    console.log('Timeout API error - PID: 03-get-metadata-search-status');  
    console.error(err);
  }
}, []);


/*
//--## Get tagging status
const getTaggingProcessStatus = useCallback(async () => {      
  
  try {
      
      var parameters = {                         
                      processId : "06-get-tagging-process-status", 
                      scanId : currentScanId.current
      };        
      
      const api = createApiObject({ method : 'POST', async : true });          
      api.onload = function() {                    
                if (api.status === 200) {    
                    var response = JSON.parse(api.responseText)?.['response']; 
                    var message = JSON.parse(response['message']);                     
                    if (response['status'] === 'completed') {
                        setTaggingStatus('completed');   
                        showMessage({ type : "success", content : `Tagging process ${currentScanId.current} has been completed. Success (${message['success'] || 0 }), Errors (${message['error'] || 0 }).` });                        
                    } else if (response['status'] === 'failed') {
                        setTaggingStatus('failed');
                    } else {                      
                      timeoutRef.current = setTimeout(getTaggingProcessStatus, 5000); 
                    }                                           
                    
                }
      };
      api.send(JSON.stringify({ parameters : parameters })); 

  } catch (err) {
    console.log('Timeout API error - PID: 03-get-metadata-search-status');  
    console.error(err);
  }
}, []);


*/


//--## Start tagging process
const handleStartTaggingProcess = useCallback(() => {
      
  try {
   
        setTaggingStatus("in-progress");
        var parameters = {                         
                        processId : "05-create-tagging-process", 
                        scanId : currentScanId.current,
                        tags : tagList.current,
                        action : actionTags.current                                      
        };        
        

        const api = createApiObject({ method : 'POST', async : true });          
        api.onload = function() {                    
                  if (api.status === 200) {    
                      var response = JSON.parse(api.responseText)?.['response'];                                                                  
                      getTaggingProcessStatus();
                  }
        };
        api.send(JSON.stringify({ parameters : parameters }));  
        
        
  }
  catch(err){
        console.log(err);
        console.log('Timeout API error - PID: 05-create-tagging-process');                    
  }
  
}, [getTaggingProcessStatus]);



//--## Convert list of tags to tokens
const convertTagsToTokens = (tags) => {
  if (tags.length > 0) {
        return tags.map((tag, index) => ({
          label: `${tag.key} = ${tag.value}`,
          dismissLabel: `Remove ${tag.key}`,
          value: String(index)
        }));
  }
};


//--## Goto to compliance page
function handleGotoDashboard(){
  navigate('/compliance');
}


  //--## Init method
  useEffect(() => {
      gatherMetadataInformation();        
    }, []);
    
       
  return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout            
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/workloads/"} />}
            navigationOpen={false}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <div style={{"padding" : "1em"}}>
                        
                        <br/>                        
                        <br/>
                        <Header variant="h1">
                            Identifier :  {currentScanId.current}                                     
                        </Header>
                        <Wizard
                          i18nStrings={{
                                        stepNumberLabel: stepNumber =>
                                          `Step ${stepNumber}`,
                                        collapsedStepsLabel: (stepNumber, stepsCount) =>
                                          `Step ${stepNumber} of ${stepsCount}`,
                                        skipToButtonLabel: (step, stepNumber) =>
                                          `Skip to ${step.title}`,
                                        navigationAriaLabel: "Steps",
                                        cancelButton: "Cancel",
                                        previousButton: "Previous",
                                        nextButton: "Next",
                                        submitButton: "Close",
                                        optional: "optional"
                          }}
                          onNavigate={({ detail }) => {
                            setActiveStepIndex(detail.requestedStepIndex);
                            currentStep.current = detail.requestedStepIndex;
                            if (detail.requestedStepIndex == 1)
                            {
                               pageId.current = 0;
                               getScanResults();
                            }
                            setApplicationMessage([]);
                            
                          }}
                          onSubmit={
                            handleGotoDashboard
                          }
                          onCancel={
                            handleGotoDashboard
                          }
                          activeStepIndex={activeStepIndex}
                          isLoadingNextStep={ ( searchStatus== "in-progress"  ? true : false ) }
                          steps={[                                                        
                            {
                              title: "Manage tags",
                              description: "Select action to be performed and define list of tags for resources selected.",
                              content: (
                                        <Container>
                                          <FormField label={"Action"}>
                                          <Select
                                              selectedOption={selectedAction}
                                              onChange={({ detail }) => {
                                                  setSelectedAction(detail.selectedOption);
                                                  actionTags.current = detail.selectedOption['value'];
                                                }
                                              }
                                              options={[
                                                { label: "Add tags", value: 1, iconName: "status-positive" },
                                              ]}
                                          />
                                          <br/>
                                          </FormField>                                         
                                          <FormField label={"Tags"}>
                                              <TokenGroupReadOnly01
                                                      items={convertTagsToTokens(selectedTags)}                                     
                                                      limit={10}
                                              />                          
                                          </FormField>  
                                      </Container>

                              )
                            },
                            {
                              title: "Resources",
                              description: "Review resources discovered, define to which ones apply tag actions, this definition will be used by tagging process.",
                              content: (
                                <div>                                                                       
                                    <Container>
                                        <CustomTable02
                                            columnsTable={columnsTableResources}
                                            visibleContent={visibleContentResources}
                                            dataset={datasetResources}
                                            title={"Resources"}
                                            description={""}
                                            pageSize={20}
                                            onSelectionItem={( item ) => {                                                                                    
                                                resourceId.current = item[0];                                                
                                              }
                                            }
                                            extendedTableProperties = {
                                                { 
                                                    variant : "borderless",
                                                    loading : (searchStatus=="in-progress" ? true : false )

                                            }                                                
                                            }
                                            tableActions={
                                                        <SpaceBetween
                                                          direction="horizontal"
                                                          size="xs"
                                                        >
                                                          <Button iconName="refresh" onClick={() => { 
                                                                  pageId.current = 0;
                                                                  getScanResults();
                                                          }}></Button>
                                                          <Select
                                                              selectedOption={selectedFilterAction}
                                                              onChange={({ detail }) => {
                                                                  setSelectedFilterAction(detail.selectedOption);
                                                                  filterAction.current = detail.selectedOption['value'] ;
                                                                  pageId.current = 0;
                                                                  getScanResults();
                                                                }
                                                              }
                                                              options={[
                                                                { label: "Filter-In", value: "1" },
                                                                { label: "Filter-Out", value: "2" },
                                                                { label: "All", value: "3" }                                                                
                                                              ]}
                                                          />
                                                          <ButtonDropdown
                                                                      onItemClick={( item ) => {
                                                                        actionType.current = item.detail.id;
                                                                        updateResourceAction();
                                                                        }
                                                                      }
                                                                      items={[
                                                                        { text: "Move to Filter-In", id: "1" },
                                                                        { text: "Move to Filter-Out", id: "2" }
                                                                      ]}
                                                                      variant="primary"
                                                              >
                                                                Action
                                                          </ButtonDropdown>

                                                          
                                                        </SpaceBetween>
                                            }

                                            pageSize={pageSize.current}
                                            totalPages={totalPages.current}
                                            totalRecords={totalRecords.current}
                                            pageId={pageId.current + 1}
                                            onPaginationChange={( item ) => {                                                                                                                                        
                                                pageId.current = item - 1;       
                                                getScanResults();                                        
                                              }
                                            }
                                                                    
                                          />
                                      </Container>
                                  </div>
                              )
                            },
                            {
                              title: "Launch tagging process",
                              description: "Start tagging process for resources according actions selected.",
                              content: (
                                          <Container>
                                              <Flashbar items={applicationMessage} />
                                              <br/>
                                              <KeyValuePairs
                                                  columns={4}
                                                  items={[
                                                    {
                                                      label: "Process identifier",
                                                      value: currentScanId.current,                                                      
                                                    }, 
                                                    {
                                                      label: "Action",
                                                      value: (
                                                        <StatusIndicator
                                                          type={ ( selectedAction['value'] == 1 ? "success" : "error")}
                                                        >
                                                            {selectedAction['label']}
                                                        </StatusIndicator>
                                                      )
                                                    },                                                                                                       
                                                    {
                                                      label: "Resources",
                                                      value: totalRecords.current,                                                      
                                                    },                                                    
                                                    {
                                                      label: "Tags",
                                                      value: setSelectedTags.length,                                                      
                                                    },                                                    
                                                  ]}
                                                />
                                              <br/>
                                              <Alert
                                                      statusIconAriaLabel="Info"
                                                      header="By proceeding with this tagging process for AWS resources, you acknowledge and agree to the following:"
                                                    >
                                                      <br/>
                                                      1.- You understand that this process will modify resource tags across multiple AWS resources in your account(s).
                                                      <br/>
                                                      <br/>
                                                      2.- You have reviewed and verified the tagging specifications and confirm they align with your organization's tagging strategy and compliance requirements.
                                                      <br/>
                                                      <br/>
                                                      3.-You have taken necessary backups and/or documented the current tag state of affected resources before proceeding.
                                                      <br/>
                                                      <br/>
                                                      4.- You confirm you have the necessary permissions and authority to perform these changes.
                                                      <br/>
                                                      <br/>
                                                      5.-You accept full responsibility for any unintended consequences that may arise from this mass tagging operation, effects on automated processes that rely on tags, potential disruption to existing tag-based permissions or policies.
                                                      <br/>
                                                      <br/>                                                      
                                                      By proceeding, you indicate that you have read, understood, and agreed to the above statements.
                                                      <br/>
                                                      <br/>                                                      
                                                      <Checkbox
                                                          onChange={({ detail }) =>
                                                            setCheckedKnowledge(detail.checked)
                                                          }
                                                          checked={checkedKnowledge}
                                                          disabled={( taggingState.current == "Not-Started" ? false : true )}
                                                        >
                                                          I acknowledge.
                                                        </Checkbox>
                                                        
                                              </Alert>
                                              <br/>
                                              { ( taggingState.current == "Not-Started"  ) &&
                                                          <>
                                                            <Box>
                                                              <SpaceBetween direction="horizontal" size="xs">
                                                                <Button variant="primary" 
                                                                  onClick={handleStartTaggingProcess}                                                                   
                                                                  disabled={ ( ( taggingStatus=="in-progress" || checkedKnowledge == false ||  ( filterAction.current == "2" && totalRecords.current > 0) )  ? true : false )}
                                                                  loading={(taggingStatus=="in-progress" ? true : false )}
                                                                  style={{ "width": "600px"}}
                                                                >
                                                                  { ( selectedAction['value'] == 1 ? "Start adding tags" : "Start removing tags")}
                                                                </Button>
                                                              </SpaceBetween>
                                                            </Box>
                                                            <br/>
                                                          </>
                                              }
                                            
                                          </Container>
                              )
                            }
                          ]}
                        />
                          
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


          <Modal
            onDismiss={() => setVisibleShowMetadata(false)}
            visible={visibleShowMetadata}
            size={"max"}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                  <Button variant="primary" onClick={() => setVisibleShowMetadata(false)} >Close</Button>
                </SpaceBetween>
              </Box>
            }
            header={
                      <Header
                      variant="h1"
                      description={"Metadata definition for the resource."}
                    >
                      Resource metadata
                    </Header>
            }            
          >            
              <CodeEditor01
                format={"json"}
                value={metadata}
                readOnly={true}
              />
          </Modal>

          <Modal
            onDismiss={() => setVisibleTaggingErrors(false)}
            visible={visibleTaggingErrors}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="primary"  
                              onClick={() => { 
                                setVisibleTaggingErrors(false);
                                    }}
                      >
                          Close
                      </Button>                     
                </SpaceBetween>
              </Box>
            }
            header="Tagging errors"
            size="max"
          >
              <CodeEditor01
                format={"json"}
                value={JSON.stringify(datasetTagErrors,null,4)}
                readOnly={true}
              />
          </Modal>

        
        
    </div>
  );
}

export default Application;




