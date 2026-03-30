import {useState,useEffect,useRef, useCallback} from 'react'

//--## CloudScape components
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
        Link,
        SplitPanel,
        Tabs,
        Badge,
        Container,
        KeyValuePairs,
        StatusIndicator,
        Toggle
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import { createLabelFunction, customFormatNumberShort, calculateDuration } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";
import CustomTable02 from "../components/Table02";
import CustomTable03 from "../components/Table03";
import NativeChartPie01 from "../components/NativeChartPie-01";
import CustomMetric01 from "../components/Metric01";
import CodeEditor01  from '../components/CodeEditor01';
import ParametersViewer from '../components/ParametersViewer-01';
import ProcessLogsComponent from '../components/ProcessLogs-01';
import TokenGroupReadOnly01 from '../components/TokenGroupReadOnly01';
import WhereClauseViewer01 from '../components/WhereClauseViewer01';
import AccountEditorComponent from '../components/AccountEditor-01';
import RegionEditorComponent from '../components/RegionEditor-01';
import ServiceEditorComponent from '../components/ServiceEditor-01';
import TagEditorComponent from '../components/TagEditor-01';
import WhereClauseBuilder01 from '../components/WhereClauseBuilder01';



export const splitPanelI18nStrings: SplitPanelProps.I18nStrings = {
  preferencesTitle: 'Split panel preferences',
  preferencesPositionLabel: 'Split panel position',
  preferencesPositionDescription: 'Choose the default split panel position for the service.',
  preferencesPositionSide: 'Side',
  preferencesPositionBottom: 'Bottom',
  preferencesConfirm: 'Confirm',
  preferencesCancel: 'Cancel',
  closeButtonAriaLabel: 'Close panel',
  openButtonAriaLabel: 'Open panel',
  resizeHandleAriaLabel: 'Resize split panel',
};

//import '@aws-amplify/ui-react/styles.css';


//--## Main function
function Application() {

  
    //-- Variable for split panels
    const [splitPanelShow,setsplitPanelShow] = useState(false);
    const [splitPanelSize, setSplitPanelSize] = useState(350);
  

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);

    //-- Customize mode for create modal
    const [customizeMode, setCustomizeMode] = useState(false);

           
    //-- Selected scanning process
    var currentScanId = useRef({});
    const [isSelectMetadataBase,setIsSelectMetadataBase] = useState(false);
   

    //-- Table process columns
    const columnsTableProcess = [          
          {id: 'scan_id',header: 'Identifier',cell: item => (            
                <Link 
                  href={`/compliance/process/?scan_id=${item.scan_id}`} 
                  target="_blank"
                  external
                >
                  {item.scan_id}
                </Link>
              )  ,ariaLabel: createLabelFunction('scan_id'),sortingField: 'scan_id',},                                 
          {id: 'name',header: 'Name',cell: item => item.name,ariaLabel: createLabelFunction('name'),sortingField: 'name',},
          {id: 'status',header: 'Status',cell: item => ( 
            <StatusIndicator type={item['status'] == "completed" ? "success" : item['status'] == "in-progress" ? "in-progress" : "error"}>
              {item['status'] == "completed" ? "Available" : item['status'] == "in-progress" ? "In-Progress" : "Unknown"}
            </StatusIndicator>
          ),ariaLabel: createLabelFunction('status'),sortingField: 'status',},                                 
          {id: 'start_time',header: 'Creation time',cell: item => item.start_time,ariaLabel: createLabelFunction('start_time'),sortingField: 'start_time',},
          {id: 'duration',header: 'Duration',cell: item => calculateDuration(item.start_time, item.end_time),ariaLabel: createLabelFunction('duration'),sortingField: 'duration',},
          {id: 'resources',header: 'Resources',cell: item => customFormatNumberShort(item.resources,0),ariaLabel: createLabelFunction('resources'),sortingField: 'resources',},
          {id: 'in_compliance',header: 'In-Compliance',cell: item => (
            <Badge color="green">{customFormatNumberShort(item.in_compliance || 0, 0)}</Badge>
          ),ariaLabel: createLabelFunction('in_compliance'),sortingField: 'in_compliance',},
          {id: 'out_compliance',header: 'Out-Compliance',cell: item => (
            <Badge color="red">{customFormatNumberShort(item.out_compliance || 0, 0)}</Badge>
          ),ariaLabel: createLabelFunction('out_compliance'),sortingField: 'out_compliance',},
    ];
    const visibleTableProcess = ['scan_id', 'name', 'status', 'start_time', 'duration', 'resources', 'in_compliance', 'out_compliance'];
    const [itemsTableProcess,setItemsTableProcess] = useState([]);   


    //-- Table resources columns
    const columnsTableResources = [
      {id: 'action',header: 'State',cell: item => ( 
        <StatusIndicator type={item['action'] == 2 ? "success" : item['action'] == 1 ? "error" : "pending"}>
          {item['action'] == 2 ? "In-Compliance" : item['action'] == 1 ? "Out-Compliance" : "Unknown"}
        </StatusIndicator>
      ),ariaLabel: createLabelFunction('action'),sortingField: 'action',},                                 
      {id: 'account',header: 'Account',cell: item => item['account'],ariaLabel: createLabelFunction('account'),sortingField: 'account',},
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
      {id: 'arn',header: 'Arn',cell: item => item['arn'],ariaLabel: createLabelFunction('arn'),sortingField: 'arn',},  
      
    ];
    const visibleContentResources = ['action', 'account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];
    const [datasetResources,setDatasetResources] = useState([]);


    //-- Paging    
    const pageId = useRef(0);
    var totalPages = useRef(1);
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    var fetchSize = useRef(100);

    //-- Table key for forcing refresh
    const [tableKey, setTableKey] = useState(0);

    //-- Process logs
    const [processLogs, setProcessLogs] = useState("");
      

    //-- Create Metadatabase Options
    const [selectedAccounts,setSelectedAccounts] = useState([]);
    const [selectedRegions,setSelectedRegions] = useState([]);
    const [selectedServices,setSelectedServices] = useState([]);
    const [selectedFilterText,setSelectedFilterText] = useState("");
    const [selectedTags,setSelectedTags] = useState([]);

    const accountList = useRef([]);
    const regionList = useRef([]);
    const serviceList = useRef([]);
    const filterListText = useRef("");
    const tagList = useRef([]);
    
    const [inputAccounts, setInputAccounts] = useState([]);
    const [inputRegions, setInputRegions] = useState([]);
    const [inputServices, setInputServices] = useState([]);

    
    const [visibleCreateMetadataBase, setVisibleCreateMetadataBase] = useState(false);
    const [visibleDeleteMetadataBase, setVisibleDeleteMetadataBase] = useState(false);

    const [datasetProfiles,setDatasetProfiles] = useState([]);
    const [selectedProfile,setSelectedProfile] = useState([]);
    var currentParameters = useRef({});

    const [metadataBaseName,setMetadataBaseName] = useState("");
    var currentMetadataBaseName = useRef("");


    //-- Metadata Information
    const [datasetMetadataInformation,setDatasetMetadataInformation] = useState([]);


    //-- Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);

    const columnsTableTags = [
      {id: 'key',header: 'Key',cell: item => item.key,ariaLabel: createLabelFunction('key'),sortingField: 'key', width : "250px"},
      {id: 'value',header: 'Value',cell: item => item.value,ariaLabel: createLabelFunction('value'),sortingField: 'value',},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags,setItemsTableTags] = useState([]);


    //-- Modal Metadata
    const [visibleShowMetadata, setVisibleShowMetadata] = useState(false);
    const [metadata,setMetadata] = useState("");


    //-- Filter Action
    const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Out-Compliance', value : "1" });
    const filterAction = useRef("1");


    //-- Compliance
    const [complianceData, setComplianceData] = useState({           
            summary : [],
            inCompliance : [],
            outCompliance : []
    });




    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Content-Type","application/json");            
        return xhr;
    }




    //--## Get Dataset Resources
    async function getDatasetResources(){
      try {
          
            var parameters = {                         
                      processId : 'metadata::api-001-get-metadata-results', 
                      scanId : currentScanId.current['scan_id'],                      
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
                          setDatasetResources(response['resources'])                            
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 01-get-metadata-results');                  
      }
    };




    //--## Get Dataset Resources Prefetch
    async function fetchDatasetResources({ page, limit }){
      console.log('=== fetchDatasetResources called ===');
      console.log('Parameters:', {
        page,
        limit,
        scanId: currentScanId.current['scan_id'],
        action: filterAction.current
      });
      
      return new Promise((resolve, reject) => {
            try {
                  var parameters = {                         
                                  processId : 'metadata::api-001-get-metadata-results', 
                                  scanId : currentScanId.current['scan_id'],                      
                                  action : filterAction.current,
                                  page : page,
                                  limit : limit              
                  };             
                  

                  const api = createApiObject({ method : 'POST', async : true });          
                  api.onload = function() {                    
                            if (api.status === 200) {    
                                var response = JSON.parse(api.responseText)?.['response'];                             
                                totalPages.current = response['pages'];            
                                totalRecords.current = response['records'];            
                                
                                console.log('API Response:', {
                                  resourcesCount: response['resources']?.length || 0,
                                  totalRecords: response['records'] || 0,
                                  pages: response['pages'] || 0
                                });
                                
                                resolve({
                                      resources: response['resources'],
                                      totalRecords: response['records'],
                                      pages: response['pages']
                                });
                            } else {
                                console.error('API error:', api.status);
                                reject(new Error('API error'));
                            }
                  };
                  
                  api.onerror = function() {
                        console.error('Network error');
                        reject(new Error('Network error'));
                  };
                  
                  api.send(JSON.stringify({ parameters : parameters }));            
                  
            }
            catch(err){
                  console.log(err);
                  console.log('Timeout API error - PID: 01-get-metadata-results');
                  reject(err);
            }
      });
    };




    //--## Get Process Logs
    async function getProcessLogs(){
      try {
          
            var parameters = {                         
                      processId : 'tagger::api-106-get-scan-logs', 
                      scanId : currentScanId.current['scan_id']
            };             
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                             
                          if (response['exists']) {
                            setProcessLogs(response['content']);
                          } else {
                            setProcessLogs('No logs available for this process.');
                          }
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: tagger::api-106-get-scan-logs');                  
      }
    };




    //--## Get Compliance Score
    async function getComplianceScore(){
      try {
          
            var parameters = {                         
                      processId : 'metadata::api-009-get-compliance-score', 
                      scanId : currentScanId.current['scan_id']            
            };             
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                                             
                          console.log(response);                                              
                          setComplianceData(response);

                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 22-compliance-score');                  
      }
    };

    

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
          
          setSelectedFilterText(parameters['filter']);
          filterListText.current = parameters['filter'];

          //-- Create tag list
          var tags = [];
          parameters['tags'].forEach( element => {
            tags.push({ key: element['key'], value: element['value'] });
          });          
          tagList.current = tags;

      
    }


  
    //--## Gather Profiles
    async function gatherProfiles(){
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
                processId : 'metadata::api-005-get-dataset-metadata-bases',
                type : 3,
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




    //--## Create Metadata Base
    function createMetadataBase(){
          
        var mtBaseName = "compliance-base-" + Math.random().toString(36).substring(2,12);       
        currentMetadataBaseName.current = mtBaseName;         
        setMetadataBaseName(mtBaseName);
        setCustomizeMode(false);
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
                ruleset['tags'] = tagList.current;
                ruleset['action'] = 0;
                ruleset['filter'] = filterListText.current;

                var parameters = {                         
                                processId : 'metadata::api-002-create-metadata-search', 
                                scanId : scanId,
                                name : currentMetadataBaseName.current,
                                ruleset : ruleset,
                                type : 3                         
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
                                processId : 'metadata::api-008-delete-metadata-base', 
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




    //--## Show Tags
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
                            processId : 'metadata::api-004-get-resource-metadata', 
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




    //--## Export Data to CSV
    const exportDataToCsv = (data,fileName) => {
      const csvData = new Blob([convertToCSV(data)], { type: 'text/csv' });
      const csvURL = URL.createObjectURL(csvData);
      const link = document.createElement('a');
      link.href = csvURL;
      link.download = `${fileName}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    };




    //--## Convert to CSV
    const convertToCSV = (objArray) => {
        const array = typeof objArray !== 'object' ? JSON.parse(objArray) : objArray;
        let str = '';
    
        for (let i = 0; i < array.length; i++) {
          let line = '';
          for (let index in array[i]) {
            if (line !== '') line += ',';
    
            line += array[i][index];
          }
          str += line + '\r\n';
        }
        return str;
    };




    //--## Format JSON
    function JSONPretty(obj) {      
      try {     
            return JSON.stringify(JSON.parse(obj),null,4);        
      } catch (error) {        
        return "";
      }
    }



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherProfiles();
        getMetadataBases();
    }, []);
    
    
    
    
  //--## Rendering
  return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout            
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/compliance/"} />}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            splitPanelOpen={splitPanelShow}
            onSplitPanelToggle={() => setsplitPanelShow(false)}            
            onSplitPanelResize={
                          ({ detail: { size } }) => {
                          setSplitPanelSize(size);
                      }
            }
            splitPanelSize={splitPanelSize}
            splitPanel={
                      <SplitPanel  
                          header={
                                <div>
                                { currentScanId.current['scan_id'] && 
                                    <Header 
                                        variant="h3"
                                        actions={
                                          <Button
                                            iconName="external"
                                            variant="primary"
                                            href={`/compliance/process/?scan_id=${currentScanId.current['scan_id']}`}
                                            target="_blank"
                                            ariaLabel="Open in new tab"
                                          >
                                            Open details
                                          </Button>
                                        }
                                    >
                                          {"Identifier : "+ currentScanId.current['scan_id'] }
                                    </Header>                                  
                                }
                                </div>
                            
                          } 
                          i18nStrings={splitPanelI18nStrings} 
                          onSplitPanelToggle={({ detail }) => {
                                         
                                        }
                                      }
                      >
                        {/* ----### Split Panel Tabs */}
                        <Tabs
                            tabs={[
                              {
                                label: "Summary",
                                id: "summary",
                                content: 
                                        <div>

                                              <table style={{"width":"100%"}}>
                                                <tr>  
                                                    <td valign="middle" style={{"width":"33%", "padding-right": "2em", "text-align": "center"}}>  
                                                          <Header variant="h2">
                                                              Summary      
                                                          </Header>
                                                          <NativeChartPie01 
                                                              title={"Total resources by tag action"}
                                                              extendedProperties = {
                                                                { 
                                                                  hideFilter : true, 
                                                                  variant : "donut",
                                                                  innerMetricDescription : "resources",
                                                                  innerMetricValue : complianceData['summary']['total']
                                                                } 
                                                              }
                                                              height={"250"}
                                                              series={[
                                                                {
                                                                  title: "In-Compliance",
                                                                  value: complianceData['summary']['in_compliance']                                              
                                                                },
                                                                {
                                                                  title: "Out-Compliance",
                                                                  value: complianceData['summary']['out_compliance']                                              
                                                                }                                                                                                    
                                                              ]}
                                                          />      
                                                    </td>
                                                    <td valign="middle" style={{"width":"33%", "padding-right": "2em", "text-align": "center"}}>  
                                                          <Header variant="h2">
                                                              In-Compliance
                                                          </Header>
                                                          <NativeChartPie01 
                                                              title={"Total resources by tag action"}
                                                              extendedProperties = {
                                                                { 
                                                                  hideFilter : true, 
                                                                  variant : "donut",
                                                                  innerMetricDescription : "resources",
                                                                  innerMetricValue : complianceData['summary']['in_compliance']
                                                                } 
                                                              }
                                                              height={"250"}
                                                              series={complianceData['in_compliance']}
                                                          />      
                                                    </td>
                                                    <td valign="top" style={{"width":"33%", "padding-right": "2em", "text-align": "left"}}>  
                                                          <Header variant="h2">
                                                              Out-Compliance
                                                          </Header>
                                                           <NativeChartPie01 
                                                              title={"Total resources by tag action"}
                                                              extendedProperties = {
                                                                  { 
                                                                    hideFilter : true, 
                                                                    variant : "donut",
                                                                    innerMetricDescription : "resources",
                                                                    innerMetricValue : complianceData['summary']['out_compliance']
                                                                  } 
                                                              }
                                                              variant={"donut"}
                                                              height={"250"}
                                                              series={complianceData['out_compliance']}
                                                          />      
                                                            
                                                            
                                                    </td>
                                                </tr>
                                            </table>
                                            
                                        </div>
                              },
                              {
                                label: "Process Details",
                                id: "details",
                                content: 
                                        <div>
                                            <Container>
                                              <KeyValuePairs
                                                columns={3}
                                                items={[
                                                  {
                                                    label: "Process ID",
                                                    value: currentScanId.current['scan_id'] || '-'
                                                  },
                                                  {
                                                    label: "Name",
                                                    value: currentScanId.current['name'] || '-'
                                                  },
                                                  {
                                                    label: "Status",
                                                    value: (
                                                      <StatusIndicator type={currentScanId.current['status'] == "completed" ? "success" : currentScanId.current['status'] == "in-progress" ? "in-progress" : "error"}>
                                                        {currentScanId.current['status'] == "completed" ? "Available" : currentScanId.current['status'] == "in-progress" ? "In-Progress" : "Unknown"}
                                                      </StatusIndicator>
                                                    )
                                                  },
                                                  {
                                                    label: "Creation Time",
                                                    value: currentScanId.current['start_time'] || '-'
                                                  },
                                                  {
                                                    label: "Completed Time",
                                                    value: currentScanId.current['end_time'] || '-'
                                                  },
                                                  {
                                                    label: "Duration",
                                                    value: calculateDuration(currentScanId.current['start_time'], currentScanId.current['end_time'])
                                                  },
                                                  {
                                                    label: "Total Resources",
                                                    value: (
                                                      <Badge color="blue">
                                                        {customFormatNumberShort(currentScanId.current['resources'] || 0, 0)}
                                                      </Badge>
                                                    )
                                                  },
                                                  {
                                                    label: "In-Compliance",
                                                    value: (
                                                      <Badge color="green">
                                                        {customFormatNumberShort(complianceData['summary']['in_compliance'] || 0, 0)}
                                                      </Badge>
                                                    )
                                                  },
                                                  {
                                                    label: "Out-Compliance",
                                                    value: (
                                                      <Badge color="red">
                                                        {customFormatNumberShort(complianceData['summary']['out_compliance'] || 0, 0)}
                                                      </Badge>
                                                    )
                                                  }
                                                ]}
                                              />
                                            </Container>
                                        </div>
                              },
                              {
                                label: "Resources",
                                id: "resources",
                                content: 
                                        <div>  

                                            <Container>
                                                <CustomTable03
                                                      key={tableKey}
                                                      columnsTable={columnsTableResources}
                                                      visibleContent={visibleContentResources}
                                                      title={"Resource search results"}
                                                      description={"AWS resources evaluated during the compliance assessment. Use filters to view in-compliance or out-compliance resources."}
                                                      fetchSize={fetchSize.current}
                                                      displayPageSize={pageSize.current}
                                                      totalRecords={totalRecords.current}
                                                      selectionType="single"
                                                      onFetchData={fetchDatasetResources}
                                                      onSelectionChange={( items ) => {
                                                          console.log('=== Selection changed ===');
                                                          console.log('Selected items count:', items.length);
                                                          console.log('Selected items:', items);
                                                      }}
                                                      onPageChange={(pageInfo) => {
                                                          console.log('=== Page changed ===');
                                                          console.log('Page info:', {
                                                              pageIndex: pageInfo.pageIndex,
                                                              chunkIndex: pageInfo.chunkIndex,
                                                              totalPages: pageInfo.totalPages
                                                          });
                                                      }}
                                                      tableActions={
                                                                  <SpaceBetween
                                                                    direction="horizontal"
                                                                    size="xs"
                                                                  >
                                                                    
                                                                    <Select
                                                                        selectedOption={selectedFilterAction}
                                                                        onChange={({ detail }) => {
                                                                            setSelectedFilterAction(detail.selectedOption);
                                                                            filterAction.current = detail.selectedOption['value'] ;
                                                                            pageId.current = 0;
                                                                            setTableKey(prev => prev + 1);
                                                                          }
                                                                        }
                                                                        options={[
                                                                          { label: "Out-Compliance", value: "1" },
                                                                          { label: "In-Compliance", value: "2" }                                                      
                                                                        ]}
                                                                    />                                                              
                                                                    <Button onClick={() => { 
                                                                            exportDataToCsv(datasetResources,"resources");
                                                                    }}>
                                                                      Export to CSV
                                                                    </Button>
                                                                  
                                                                  </SpaceBetween>
                                                      }
                                                    />
                                              </Container>  
                                              
                                        </div>
                              },
                              {
                                label: "Parameters",
                                id: "parameters",
                                content: 
                                        <div>  
                                              <ParametersViewer
                                                value={currentScanId.current['parameters']}
                                              />
                                        </div>
                              },
                              {
                                label: "Logs",
                                id: "logs",
                                content: 
                                        <div>
                                            <ProcessLogsComponent
                                              logs={processLogs}
                                              theme="dark"
                                              headerText="Process Logs"
                                              defaultExpanded={true}
                                              variant="container"
                                            />
                                        </div>
                              }
                            ]}
                          />
                            
                      </SplitPanel>
            }
            content={
                      <div style={{"padding" : "1em"}}>
                          <Flashbar items={applicationMessage} />     

                          {/* ----### Page Header */}
                          <Header variant="h1" description="Assess tag compliance across your AWS resources. Create assessments, review compliance scores, and launch remediation workflows.">
                              Tagging compliance
                          </Header>
                          <br/>

                          {/* ----### How it works */}
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
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Create a compliance validation</span>
                                        </div>                                                                  
                                        <SpaceBetween size="s">
                                          <div>
                                          <strong>Comprehensive Tag Audit:</strong> Automatically scan all AWS resources across your account to verify compliance with your organization's tagging policies.
                                          </div>                                         
                                        </SpaceBetween>
                                        <br/>
                                        <Button
                                              onClick={() => { 
                                                createMetadataBase();
                                              }}
                                        >
                                            Create compliance validation
                                        </Button>
                                
                                    </td>
                                    <td style={{"width":"33%", "padding-right": "2em", "text-align": "left", "vertical-align" : "top"}}>  
                                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                          <Icon name={"search"} size="medium" />
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Identify Non-Compliant Resources</span>
                                        </div>                          
                                        <strong>Detailed Compliance Reports:</strong> Review a comprehensive breakdown of which resources are properly tagged and which require attention.
                                    </td>
                                    <td style={{"width":"33%", "padding-right": "2em", "text-align": "left", "vertical-align" : "top"}}>                                      
                                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                          <Icon name={"settings"} size="medium" />
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Launch Remediation</span>
                                        </div>                          
                                        <p>Launch automated remediation workflows that can apply missing tags, correct tag values.</p>              
                                    </td>
                                </tr>
                            </table>    

                            
                          </ExpandableSection>
                          <br/>

                          {/* ----### Compliance Assessments Table */}
                          <CustomTable01
                              columnsTable={columnsTableProcess}
                              visibleContent={visibleTableProcess}
                              dataset={itemsTableProcess}
                              title={"Compliance assessments"}
                              description={"Manage and monitor compliance assessments. Select a process to view details, resources, and remediation options."}
                              pageSize={10}
                              onSelectionItem={( item ) => {
                                  currentScanId.current = item[0];  
                                  pageId.current = 0;
                                  setIsSelectMetadataBase(true);       
                                  setsplitPanelShow(true);
                                  setTableKey(prev => prev + 1);
                                  getDatasetResources();
                                  getComplianceScore();
                                  getProcessLogs();
                                }
                              }
                              tableActions={
                                              <SpaceBetween
                                                direction="horizontal"
                                                size="xs"
                                              >    
                                                
                                                <Button 
                                                        disabled={!isSelectMetadataBase}
                                                        onClick={() => { 
                                                          setVisibleDeleteMetadataBase(true);
                                                        }}
                                                >
                                                  Delete
                                                </Button>    
                                                 <Button 
                                                        onClick={() => { 
                                                          createMetadataBase();
                                                        }}
                                                >
                                                  Create
                                                </Button>                                                                                          
                                                <Button
                                                        disabled={!isSelectMetadataBase}
                                                        iconAlign="right"
                                                        iconName="external"
                                                        target="_blank"
                                                        href={"/metadata/explorer/?scan_id=" + currentScanId.current['scan_id']}
                                                >
                                                  Open Tag Explorer
                                                </Button>
                                                <Button external={false}
                                                        disabled={!isSelectMetadataBase}
                                                        iconAlign="right"
                                                        iconName="external"
                                                        target="_blank"
                                                        href={"/remediate?scan_id=" + currentScanId.current['scan_id']}                                                        
                                                        variant='primary'
                                                >
                                                  Launch remediation
                                                </Button>  
                                                <Button iconName="refresh" 
                                                        onClick={() => { 
                                                              getMetadataBases();
                                                        }}
                                                >
                                                </Button>
                                               
                                                
                                              
                                              </SpaceBetween>
                              }
                          />                          
                          
                  </div>
                
            }
          />
       
          
          {/* ----### Create Modal */}
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
                          description={"Scan AWS resources across your accounts to verify compliance"}
                        >
                          Create compliance discovery
                        </Header>
                }            
              >            
                 
                  <table style={{"width":"100%"}}>
                    <tr>  
                        <td valign="bottom" style={{"width":"25%", "padding-right": "2em"}}> 
                          <FormField
                              label="Name"
                              description="Provide the name for the metadata base."
                            >
                              <Input 
                                  value={metadataBaseName}
                                  onChange={({ detail }) => {
                                      setMetadataBaseName(detail.value);
                                      metadataBaseName.current = detail.value;
                                  }}
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
                        <td valign="bottom" style={{"width":"15%", "padding-right": "2em"}}>  
                          <FormField label={"Customize"}>
                              <Toggle
                                  onChange={({ detail }) => setCustomizeMode(detail.checked)}
                                  checked={customizeMode}
                              >
                                  {customizeMode ? "On" : "Off"}
                              </Toggle>
                          </FormField>
                        </td>
                        <td valign="middle" style={{"width":"60%"}}>
                        </td>                                        
                    </tr>
                  </table>  
                  <br/>  

                  {/* ----### Accounts */}                          
                  <Container
                    header={
                            <Header variant="h2" description="AWS accounts in-scope for the compliance assessment.">
                                Accounts
                            </Header>
                  }
                  >
                        <AccountEditorComponent
                            value={selectedAccounts.map(a => a.value || a)}
                            readOnly={!customizeMode}
                            onChange={({ detail }) => {
                                const tokens = detail.value.map(v => ({ label: v, value: v }));
                                setSelectedAccounts(tokens);
                                accountList.current = tokens;
                            }}
                        />
                  </Container>
                  <br/>

                  {/* ----### Regions */}                          
                  <Container
                    header={
                            <Header variant="h2" description="AWS regions in-scope for the compliance assessment.">
                                Regions
                            </Header>
                  }
                  >
                        <RegionEditorComponent
                            value={selectedRegions.map(r => r.value || r)}
                            readOnly={!customizeMode}
                            onChange={({ detail }) => {
                                const tokens = detail.value.map(v => ({ label: v, value: v }));
                                setSelectedRegions(tokens);
                                regionList.current = tokens;
                            }}
                        />
                  </Container>
                  <br/>

                  {/* ----### Services */}                          
                  <Container
                    header={
                            <Header variant="h2" description="AWS services in-scope for the compliance assessment.">
                                Services
                            </Header>
                  }
                  >
                        <ServiceEditorComponent
                            value={selectedServices.map(s => s.value || s)}
                            readOnly={!customizeMode}
                            onChange={({ detail }) => {
                                const tokens = detail.value.map(v => ({ label: v, value: v }));
                                setSelectedServices(tokens);
                                serviceList.current = tokens;
                            }}
                        />
                  </Container>
                  <br/>

                  {/* ----### Advanced Filtering */}                                                
                  <Container
                        header={
                                <Header variant="h2" description="Conditions to filter AWS resources.">
                                    Advanced filtering
                                </Header>
                      }
                  >
                        <WhereClauseBuilder01
                            value={selectedFilterText}
                            readOnly={!customizeMode}
                            onChange={(newValue) => {
                                setSelectedFilterText(newValue);
                                filterListText.current = newValue;
                            }}
                        />
                  </Container>      
                  
            </Modal>


            {/* ----### Delete Modal */}
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
            header="Delete compliance base"
          >
            Do you want to delete a compliance base  <b>[{currentScanId.current['name']}]</b> ?
          </Modal>
          
          
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


          {/* ----### Metadata Modal */}
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



    </div>
  );
}

export default Application;
