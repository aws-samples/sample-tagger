import {useState,useEffect,useRef} from 'react'

//--## CloudScape components
import {
        AppLayout,
        SideNavigation,
        SpaceBetween,
        Button,
        Header,
        Box,
        Container,
        SplitPanel,
        Tabs,
        Select,
        Modal,
        Icon,
        Badge,
        KeyValuePairs,
        StatusIndicator,
        Link
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import { createLabelFunction, customFormatNumberShort, calculateDuration } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";
import CustomTable02 from "../components/Table02";
import CustomTable03 from "../components/Table03";
import NativeChartBar01 from '../components/NativeChartBar-01';
import CodeEditor01  from '../components/CodeEditor01';
import ParametersViewer from '../components/ParametersViewer-01';
import ProcessLogsComponent from '../components/ProcessLogs-01';



//-- Split panel configuration
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



//--## Main function
function Application() {

    //-- Split panel
    const [splitPanelShow,setsplitPanelShow] = useState(false);
    const [splitPanelSize, setSplitPanelSize] = useState(350);


    //-- Charts
    const [chartSummaryResources, setChartSummaryResources] = useState({ added : [], removed : []});
    const [chartSummaryServices, setChartSummaryServices] = useState([]);


    //-- Table columns - Process
    const columnsTableProcess = [
                  {id: 'scan_id',header: 'ProcessId',cell: item => (
                    <Link 
                      href={`/tagger/process/?scan_id=${item.scan_id}`} 
                      target="_blank"
                      external
                    >
                      {item.scan_id}
                    </Link>
                  ),ariaLabel: createLabelFunction('scan_id'),sortingField: 'scan_id',},
                  {id: 'name',header: 'Source',cell: item => item.name,ariaLabel: createLabelFunction('name'),sortingField: 'name',},
                  {id: 'action',header: 'Action',cell: item => ( 
                    <StatusIndicator type={item['action'] == 1 ? "success" : item['action'] == 2 ? "error" : "pending"}>
                      {item['action'] == 1 ? "Tags added" : item['action'] == 2 ? "Tags removed" : "Unknown"}
                    </StatusIndicator>
                  ),ariaLabel: createLabelFunction('action'),sortingField: 'action',},                                 
                  {id: 'start_time',header: 'Inventory started',cell: item => item.start_time,ariaLabel: createLabelFunction('start_time'),sortingField: 'start_time',},
                  {id: 'end_time',header: 'Inventory ended',cell: item => item.end_time,ariaLabel: createLabelFunction('end_time'),sortingField: 'end_time',},
                  {id: 'inventory_duration',header: 'Inventory duration',cell: item => calculateDuration(item.start_time, item.end_time),ariaLabel: createLabelFunction('inventory_duration'),sortingField: 'inventory_duration',},
                  {id: 'start_time_tagging',header: 'Tagging started',cell: item => item.start_time_tagging,ariaLabel: createLabelFunction('start_time_tagging'),sortingField: 'start_time_tagging',},
                  {id: 'end_time_tagging',header: 'Tagging ended',cell: item => item.end_time_tagging,ariaLabel: createLabelFunction('end_time_tagging'),sortingField: 'end_time_tagging',},
                  {id: 'tagging_duration',header: 'Tagging duration',cell: item => calculateDuration(item.start_time_tagging, item.end_time_tagging),ariaLabel: createLabelFunction('tagging_duration'),sortingField: 'tagging_duration',},
                  {id: 'resources',header: 'Total Resources',cell: item => (
                    <Badge color="blue">{customFormatNumberShort(item.resources,0)}</Badge>
                  ),ariaLabel: createLabelFunction('resources'),sortingField: 'resources',},
                  {id: 'resources_tagged_success',header: 'Success',cell: item => (
                    <Badge color="green">{customFormatNumberShort(item.resources_tagged_success,0)}</Badge>
                  ),ariaLabel: createLabelFunction('resources_tagged_success'),sortingField: 'resources_tagged_success',},
                  {id: 'resources_tagged_error',header: 'Errors',cell: item => (
                    <Badge color="red">{customFormatNumberShort(item.resources_tagged_error,0)}</Badge>
                  ),ariaLabel: createLabelFunction('resources_tagged_error'),sortingField: 'resources_tagged_error',},                
    ];
    const visibleTableProcess = ['scan_id', 'name', 'action', 'start_time', 'inventory_duration', 'tagging_duration', 'resources', 'resources_tagged_success', 'resources_tagged_error'];
    const [itemsTableProcess,setItemsTableProcess] = useState([]);


    //-- Table columns - Resources
    const columnsTableResources = [
        {id: 'action',header: 'Action',cell: item => ( 
          <StatusIndicator type={item['action'] == "1" ? "success" : (item['action'] == "2" ? "error" : "pending")}>
            {item['action'] == "1" ? "Included" : (item['action'] == "2" ? "Excluded" : "Unknown")}
          </StatusIndicator>
        ), ariaLabel: createLabelFunction('action'), sortingField: 'action'},    
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
        
    ];
    const visibleContentResources = ['action', 'account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];
    const [datasetResources,setDatasetResources] = useState([]);


    //-- Paging
    const pageId = useRef(0);
    var totalPages = useRef(1);
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    var fetchSize = useRef(100); // Pre-fetch size (chunk size) for Table03


    //-- Filter Action
    const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Resources included', value : "1" });
    const filterAction = useRef("1");

    //-- Table key for forcing refresh
    const [tableKey, setTableKey] = useState(0);


    //-- Process selection
    var currentScanId = useRef({ parameters : {} });
    const [selectedProcess, setSelectedProcess] = useState(null);


    //-- Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);

    //-- Modal Delete Confirmation
    const [visibleDeleteConfirm, setVisibleDeleteConfirm] = useState(false);
    const [selectedProcessToDelete, setSelectedProcessToDelete] = useState(null);

    //-- Table columns - Tags
    const columnsTableTags = [
      {id: 'key',header: 'Key',cell: item => item.key,ariaLabel: createLabelFunction('key'),sortingField: 'key', width : "250px"},
      {id: 'value',header: 'Value',cell: item => item.value,ariaLabel: createLabelFunction('value'),sortingField: 'value',},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags,setItemsTableTags] = useState([]);


    //-- Modal Metadata
    const [visibleShowMetadata, setVisibleShowMetadata] = useState(false);
    const [metadata,setMetadata] = useState("");

    //-- Logs
    const [processLogs, setProcessLogs] = useState("");




    //--## Create API object
    function createApiObject(object){
      const xhr = new XMLHttpRequest();
      xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
      xhr.setRequestHeader("Content-Type","application/json");            
      return xhr;
    }



    //--## Get Dataset Tagging
    async function getDatasetTagging(){
      try {
          
            var parameters = {                         
                            processId : 'tagger::api-104-get-dataset-tagging'           
            };        
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {                              
                          var response = JSON.parse(api.responseText)?.['response'];                      
                          setItemsTableProcess(response['processes']);  
                          // Summary comes from API in DESC order (newest first), reverse to show newest on right
                          setChartSummaryResources({
                            added: [...response['summary']['added']].reverse(),
                            removed: [...response['summary']['removed']].reverse()
                          });     
                          // Services data comes from API in ASC order (oldest first), no reversal needed
                          setChartSummaryServices(response['services']);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 08-get-dataset-tagging');                  
      }
    };



    //--## Fetch Dataset Resources
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



    //--## Delete Tagging Process
    async function deleteTaggingProcess(scanId){
      try {
          
            var parameters = {                         
                      processId : 'metadata::api-008-delete-metadata-base', 
                      scanId : scanId
            };             
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                             
                          if (response['status'] === 'success') {
                            // Close modal
                            setVisibleDeleteConfirm(false);
                            setSelectedProcessToDelete(null);
                            setSelectedProcess(null);
                            
                            // Close split panel if deleted process was selected
                            if (currentScanId.current['scan_id'] === scanId) {
                              setsplitPanelShow(false);
                              currentScanId.current = { parameters : {} };
                            }
                            
                            // Refresh the table
                            getDatasetTagging();
                          }
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: metadata::api-008-delete-metadata-base');                  
      }
    };




    //--## JSON Pretty
    function JSONPretty(obj) {      
      try {     
            return JSON.stringify(JSON.parse(obj),null,4);        
      } catch (error) {        
        return "";
      }
    }



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



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        getDatasetTagging();        
    }, []);



    //--## Rendering
    return (
        <div style={{"background-color": "#f2f3f3"}}>
            <CustomHeader/>
            <AppLayout            
                toolsHide
                disableContentPaddings={true}
                breadCrumbs={breadCrumbs}
                navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/dashboard/"} />}
                contentType="table"
                splitPanelOpen={splitPanelShow}            
                onSplitPanelToggle={() => setsplitPanelShow(!splitPanelShow)}            
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
                                              href={`/tagger/process/?scan_id=${currentScanId.current['scan_id']}`}
                                              target="_blank"
                                              ariaLabel="Open in new tab"
                                            >
                                              Open details
                                            </Button>
                                          }
                                      >                                  
                                          {"Process Identifier : " + currentScanId.current['scan_id'] }
                                      </Header>
                                      }
                                    </div>
                                  
                                
                              } 
                              i18nStrings={splitPanelI18nStrings} 
                              closeBehavior="collapse"
                              onSplitPanelToggle={({ detail }) => {
                                             
                                            }
                                          }
                          >

                            {/* ----### Split Panel Tabs */}
                            <Tabs
                                tabs={[
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
                                                        label: "Source",
                                                        value: currentScanId.current['name'] || '-'
                                                      },
                                                      {
                                                        label: "Action",
                                                        value: (
                                                          <StatusIndicator type={currentScanId.current['action'] == 1 ? "success" : currentScanId.current['action'] == 2 ? "error" : "pending"}>
                                                            {currentScanId.current['action'] == 1 ? "Tags added" : currentScanId.current['action'] == 2 ? "Tags removed" : "Unknown"}
                                                          </StatusIndicator>
                                                        )
                                                      },
                                                      {
                                                        label: "Inventory Started",
                                                        value: currentScanId.current['start_time'] || '-'
                                                      },
                                                      {
                                                        label: "Inventory Ended",
                                                        value: currentScanId.current['end_time'] || '-'
                                                      },
                                                      {
                                                        label: "Inventory Duration",
                                                        value: calculateDuration(currentScanId.current['start_time'], currentScanId.current['end_time'])
                                                      },
                                                      {
                                                        label: "Tagging Started",
                                                        value: currentScanId.current['start_time_tagging'] || '-'
                                                      },
                                                      {
                                                        label: "Tagging Ended",
                                                        value: currentScanId.current['end_time_tagging'] || '-'
                                                      },
                                                      {
                                                        label: "Tagging Duration",
                                                        value: calculateDuration(currentScanId.current['start_time_tagging'], currentScanId.current['end_time_tagging'])
                                                      },
                                                      {
                                                        label: "Resources Tagged (Success)",
                                                        value: (
                                                          <Badge color="green">
                                                            {customFormatNumberShort(currentScanId.current['resources_tagged_success'] || 0, 0)}
                                                          </Badge>
                                                        )
                                                      },
                                                      {
                                                        label: "Resources Tagged (Errors)",
                                                        value: (
                                                          <Badge color="red">
                                                            {customFormatNumberShort(currentScanId.current['resources_tagged_error'] || 0, 0)}
                                                          </Badge>
                                                        )
                                                      },
                                                      {
                                                        label: "Total Resources Discovered",
                                                        value: (
                                                          <Badge color="blue">
                                                            {customFormatNumberShort(currentScanId.current['resources'] || 0, 0)}
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
                                    id: "first",
                                    content: 
                                            <div>
                                                <Container>
                                                  <CustomTable03
                                                      key={tableKey}
                                                      columnsTable={columnsTableResources}
                                                      visibleContent={visibleContentResources}
                                                      title={"Resource search results"}
                                                      description={"Resources discovered during the inventory process. Use filters to refine results."}
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
                                                                            setTableKey(prev => prev + 1); // Force Table03 refresh
                                                                          }
                                                                        }
                                                                        options={[
                                                                          { label: "Resources included", value: "1" },
                                                                          { label: "Resources excluded", value: "2" },                                                                      
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
                                    id: "second",
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
                                                  variant="footer"
                                                />
                                            </div>
                                  }
                                ]}
                              />
                                
                          </SplitPanel>
                }
                content={
                          <div style={{"padding" : "1em"}}>
                              <br/>

                              {/* ----### Dashboard Charts */}
                              <Container
                                header={
                                          <Header
                                            variant="h2"
                                            description="Monitor tagging operations across your AWS resources. View execution trends, success rates, and resource distribution by service type."
                                            actions={
                                              <SpaceBetween
                                                direction="horizontal"
                                                size="xs"
                                              >
                                               
                                                <Button variant={"primary"} href="/tagger/"
                                                >
                                                  Launch tagging process
                                                </Button>                                            
                                                 <Button iconName="refresh" onClick={() => { 
                                                          getDatasetTagging();
                                                }}></Button>
                                              </SpaceBetween>
                                            }
                                          >
                                            Tagging Operations Dashboard
                                          </Header>
                                        }
                              >
                              
                                <table style={{"width":"100%"}}>
                                    <tr>  
                                        <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>  
                                              <NativeChartBar01 
                                                  title={"Resource Tagging Activity"}
                                                  extendedProperties = {
                                                      { hideFilter : true } 
                                                  }
                                                  height={"250"}
                                                  series={[
                                                            {
                                                              title: "Tags Added",
                                                              type: "bar",
                                                              data: chartSummaryResources['added']
                                                            },                                                  
                                                            {
                                                              title: "Tags Removed",
                                                              type: "bar",
                                                              data: chartSummaryResources['removed']
                                                            },
                                                          ]}
                                              />      
                                        </td>
                                        <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>  
                                              <NativeChartBar01 
                                                  title={"Resource Distribution by Service"}
                                                  extendedProperties = {
                                                      { hideFilter : true } 
                                                  }
                                                  height={"250"}
                                                  series={chartSummaryServices}
                                              />
                                        </td>
                                    </tr>
                                </table>
                              </Container>
                              <br/>

                              {/* ----### Process History Table */}
                              <CustomTable01
                                  columnsTable={columnsTableProcess}
                                  visibleContent={visibleTableProcess}
                                  dataset={itemsTableProcess}
                                  title={"Tagging Process History"}
                                  description={"Complete history of tagging operations including inventory discovery, tagging execution, and success metrics."}
                                  pageSize={10}
                                  onSelectionItem={( item ) => {
                                      currentScanId.current = item[0];
                                      setSelectedProcess(item[0]);                                                                    
                                      setsplitPanelShow(true);
                                      pageId.current = 0;
                                      setTableKey(prev => prev + 1); // Force Table03 refresh
                                      getProcessLogs();
                                    }
                                  }
                                  tableActions={
                                    <SpaceBetween
                                      direction="horizontal"
                                      size="xs"
                                    >
                                      <Button 
                                        variant='primary'
                                        disabled={!selectedProcess}
                                        onClick={() => {
                                          if (selectedProcess) {
                                            setSelectedProcessToDelete(selectedProcess);
                                            setVisibleDeleteConfirm(true);
                                          }
                                        }}
                                      >
                                        Delete process
                                      </Button>
                                      <Button
                                        iconName="external"
                                        disabled={!selectedProcess}
                                        href={selectedProcess ? `/metadata/explorer/?scan_id=${selectedProcess.scan_id}` : '#'}
                                        target="_blank"
                                      >
                                        Open Tag Explorer
                                      </Button>
                                    </SpaceBetween>
                                  }
                              />
                              
                      </div>
                    
                }
              />

            {/* ----### Modal Tags */}
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


            {/* ----### Modal Metadata */}
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


            {/* ----### Modal Delete Confirmation */}
            <Modal
                onDismiss={() => setVisibleDeleteConfirm(false)}
                visible={visibleDeleteConfirm}
                size={"medium"}
                footer={
                  <Box float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                      <Button variant="link" onClick={() => setVisibleDeleteConfirm(false)}>Cancel</Button>
                      <Button 
                        variant="primary" 
                        onClick={() => {
                          if (selectedProcessToDelete) {
                            deleteTaggingProcess(selectedProcessToDelete.scan_id);
                          }
                        }}
                      >
                        Delete
                      </Button>
                    </SpaceBetween>
                  </Box>
                }
                header={
                          <Header
                          variant="h2"
                          description={"This action cannot be undone. All associated resources and logs will be permanently deleted."}
                        >
                          Delete tagging process
                        </Header>
                }            
            >            
                <SpaceBetween size="m">
                    <Box>
                      Are you sure you want to delete this tagging process?
                    </Box>
                    {selectedProcessToDelete && (
                      <Container>
                        <KeyValuePairs
                          columns={2}
                          items={[
                            {
                              label: "Process ID",
                              value: selectedProcessToDelete.scan_id
                            },
                            {
                              label: "Source",
                              value: selectedProcessToDelete.name
                            },
                            {
                              label: "Started",
                              value: selectedProcessToDelete.start_time
                            },
                            {
                              label: "Resources Tagged",
                              value: customFormatNumberShort(selectedProcessToDelete.resources_tagged_success || 0, 0)
                            }
                          ]}
                        />
                      </Container>
                    )}
                </SpaceBetween>
            </Modal>



        </div>
    );
}

export default Application;
