import {useState,useEffect,useRef} from 'react'
import { useSearchParams } from 'react-router-dom';

//--## CloudScape components
import {
        AppLayout,
        SideNavigation,
        ContentLayout,
        SpaceBetween,
        Button,
        Header,
        Box,
        Container,
        Tabs,
        Select,
        Badge,
        KeyValuePairs,
        StatusIndicator,
        Modal
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import { createLabelFunction, customFormatNumberShort, calculateDuration } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";
import CustomTable03 from "../components/Table03";
import CodeEditor01  from '../components/CodeEditor01';
import ParametersViewer from '../components/ParametersViewer-01';
import ProcessLogsComponent from '../components/ProcessLogs-01';
import NativeChartPie01 from "../components/NativeChartPie-01";


export const splitPanelI18nStrings = {
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

    //-- URL parameters
    const [searchParams] = useSearchParams();
    const scanId = searchParams.get('scan_id');

    //-- Application messages
    const [processData, setProcessData] = useState({});
    const [processLogs, setProcessLogs] = useState("");
    const [navigationOpen, setNavigationOpen] = useState(false);


    //-- Table columns Resources
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
              <a href='#;' style={{ "textDecoration": "none", "color": "inherit" }} onClick={() => showTags(item)}>
                  <Badge color="blue">{item['tags_number']}</Badge>
              </a>
          ),ariaLabel: createLabelFunction('tags_number'),sortingField: 'tags_number',},      
        {id: 'metadata',header: 'Metadata',cell: item => (       
              <a href='#;' style={{ "textDecoration": "none", "color": "inherit" }} onClick={() => showMetadata(item)}>
                  <Badge color="green">JSON</Badge>
              </a>
        ),ariaLabel: createLabelFunction('metadata'),sortingField: 'metadata',},      
    ];

    const visibleContentResources = ['action', 'account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];


    //-- Paging    
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    var fetchSize = useRef(100); // Pre-fetch size (chunk size) for Table03

    //-- Filter Action
    const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Out-Compliance', value : "1" });
    const filterAction = useRef("1");

    //-- Table key for forcing refresh
    const [tableKey, setTableKey] = useState(0);

    //-- Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);
    const columnsTableTags = [
        {id: 'key', header: 'Key', cell: item => item.key, ariaLabel: createLabelFunction('key'), sortingField: 'key', width: "250px"},
        {id: 'value', header: 'Value', cell: item => item.value, ariaLabel: createLabelFunction('value'), sortingField: 'value'},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags, setItemsTableTags] = useState([]);

    //-- Modal Metadata
    const [visibleShowMetadata, setVisibleShowMetadata] = useState(false);
    const [metadata, setMetadata] = useState("");

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




    //--## Get Process Data
    async function getProcessData(){
      try {
          
            var parameters = {                         
                            processId : 'metadata::api-005-get-dataset-metadata-bases',
                            type : 3
            };        
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {                              
                          var response = JSON.parse(api.responseText)?.['response'];                      
                          // Find the process with matching scan_id
                          const process = response['processes'].find(p => p.scan_id === scanId);
                          if (process) {
                            setProcessData(process);
                          }
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 13-get-dataset-metadata-bases');                  
      }
    };




    //--## Get Dataset Resources
    async function fetchDatasetResources({ page, limit }){
      console.log('=== fetchDatasetResources called ===');
      console.log('Parameters:', {
        page,
        limit,
        scanId: scanId,
        action: filterAction.current
      });
      
      return new Promise((resolve, reject) => {
            try {
                  var parameters = {                         
                                  processId : 'metadata::api-001-get-metadata-results', 
                                  scanId : scanId,                      
                                  action : filterAction.current,
                                  page : page,
                                  limit : limit              
                  };             
                  

                  const api = createApiObject({ method : 'POST', async : true });          
                  api.onload = function() {                    
                            if (api.status === 200) {    
                                var response = JSON.parse(api.responseText)?.['response'];                             
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




    //--## Get Compliance Score
    async function getComplianceScore(){
      try {
          
            var parameters = {                         
                      processId : 'metadata::api-009-get-compliance-score', 
                      scanId : scanId            
            };             
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                                             
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




    //--## Get Process Logs
    async function getProcessLogs(){
      try {
          
            var parameters = {                         
                      processId : 'tagger::api-106-get-scan-logs', 
                      scanId : scanId
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




    //--## Format JSON
    function JSONPretty(obj) {      
      try {     
            return JSON.stringify(JSON.parse(obj),null,4);        
      } catch (error) {        
        return "";
      }
    }



    //--## Show tags for specific resource
    async function showTags(item) {
        try {
            const jsonArray = Object.entries(JSON.parse(item?.['tags_list'])).map(([key, value]) => ({ key, value }));
            setItemsTableTags(jsonArray);
            setVisibleShowTags(true);
        } catch (err) {
            console.log(err);
        }
    }



    //--## Show metadata for specific resource
    async function showMetadata(item) {
        try {
            const api = createApiObject({ method: 'POST', async: true });
            api.onload = function() {
                if (api.status === 200) {
                    var response = JSON.parse(api.responseText)?.['response'];
                    setMetadata(JSON.stringify(JSON.parse(response['metadata']), null, 4));
                    setVisibleShowMetadata(true);
                }
            };
            api.send(JSON.stringify({ parameters: {
                processId: 'metadata::api-004-get-resource-metadata',
                scanId: item['scan_id'],
                seq: item['seq']
            }}));
        } catch (err) {
            console.log(err);
        }
    }




    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        if (scanId) {
          getProcessData();
          getComplianceScore();
          getProcessLogs();
        }
    }, [scanId]);




    //--## Rendering
    return (
        <div style={{"background-color": "#f2f3f3"}}>
            <CustomHeader/>
            <AppLayout            
                toolsHide
                disableContentPaddings={true}
                breadCrumbs={breadCrumbs}
                navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/compliance/"} />}
                navigationOpen={navigationOpen}
                onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
                contentType="default"
                content={
                    <ContentLayout
                        defaultPadding
                        header={
                            <Header
                                variant="h1"
                                description={"Review compliance scores, resource distribution, and remediation details for compliance assessments."}
                                actions={
                                    <SpaceBetween
                                        direction="horizontal"
                                        size="xs"
                                    >
                                        
                                        <Button 
                                            iconAlign="right"
                                            iconName="external"
                                            target="_blank"
                                            href={"/metadata/explorer/?scan_id=" + scanId}
                                        >
                                            Open Tag Explorer
                                        </Button>
                                        <Button 
                                            iconAlign="right"
                                            iconName="external"
                                            target="_blank"
                                            href={"/remediate?scan_id=" + scanId}
                                            variant='primary'
                                        >
                                            Launch remediation
                                        </Button>
                                        <Button iconName="refresh" onClick={() => { 
                                                            getProcessData();
                                                            getComplianceScore();
                                                            getProcessLogs();
                                        }}/>
                                        
                                    </SpaceBetween>
                                }
                            >
                                Compliance assessment ({scanId})
                            </Header>
                        }
                    >
                        {/* ----### Tabs Container */}
                        <Container>
                        
                            <Tabs
                                tabs={[
                                  {
                                    label: "Summary",
                                    id: "summary",
                                    content: 
                                            <div>
                                                  {/* ----### Summary Key Value Pairs */}
                                                  <Container>
                                                        <KeyValuePairs
                                                          columns={3}
                                                          items={[
                                                            {
                                                              label: "Process ID",
                                                              value: processData['scan_id'] || '-'
                                                            },
                                                            {
                                                              label: "Name",
                                                              value: processData['name'] || '-'
                                                            },
                                                            {
                                                              label: "Status",
                                                              value: (
                                                                <StatusIndicator type={processData['status'] == "completed" ? "success" : processData['status'] == "in-progress" ? "in-progress" : "error"}>
                                                                  {processData['status'] == "completed" ? "Available" : processData['status'] == "in-progress" ? "In-Progress" : "Unknown"}
                                                                </StatusIndicator>
                                                              )
                                                            },
                                                            {
                                                              label: "Creation Time",
                                                              value: processData['start_time'] || '-'
                                                            },
                                                            {
                                                              label: "Completed Time",
                                                              value: processData['end_time'] || '-'
                                                            },
                                                            {
                                                              label: "Duration",
                                                              value: calculateDuration(processData['start_time'], processData['end_time'])
                                                            },
                                                            {
                                                              label: "Total Resources",
                                                              value: (
                                                                <Badge color="blue">
                                                                  {customFormatNumberShort(processData['resources'] || 0, 0)}
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
                                                  <br/>

                                                  {/* ----### Compliance Charts */}
                                                  <Container>
                                                  <table style={{"width":"100%"}}>
                                                    <tr>  
                                                        <td valign="middle" style={{"width":"33%", "padding-right": "2em", "text-align": "center"}}>  
                                                              <Header variant="h2">
                                                                  Summary      
                                                              </Header>
                                                              <NativeChartPie01 
                                                                  title={"Total resources by compliance"}
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
                                                                  title={"Resources in compliance"}
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
                                                                  title={"Resources out of compliance"}
                                                                  extendedProperties = {
                                                                      { 
                                                                        hideFilter : true, 
                                                                        variant : "donut",
                                                                        innerMetricDescription : "resources",
                                                                        innerMetricValue : complianceData['summary']['out_compliance']
                                                                      } 
                                                                  }
                                                                  height={"250"}
                                                                  series={complianceData['out_compliance']}
                                                              />      
                                                                
                                                                
                                                        </td>
                                                    </tr>
                                                </table>
                                                </Container>
                                                
                                            </div>
                                  },

                                  //-- ----### Resources Tab
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
                                                                            setTableKey(prev => prev + 1); // Force Table03 refresh
                                                                          }
                                                                        }
                                                                        options={[
                                                                          { label: "Out-Compliance", value: "1" },
                                                                          { label: "In-Compliance", value: "2" }
                                                                        ]}
                                                                    />                                                              
                                                                   
                                                                  </SpaceBetween>
                                                      }
                                                    />
                                                </Container>  
                                            </div>
                                  },

                                  //-- ----### Parameters Tab
                                  {
                                    label: "Parameters",
                                    id: "parameters",
                                    content: 
                                            <div>  
                                                  <ParametersViewer
                                                    value={processData['parameters']}
                                                  />
                                            </div>
                                  },

                                  //-- ----### Logs Tab
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
                          <Button variant="primary" onClick={() => setVisibleShowTags(false)}>Close</Button>
                      </SpaceBetween>
                  </Box>
              }
              header={
                  <Header variant="h1" description="Tags assigned to the resource.">
                      Resource tags
                  </Header>
              }
          >
              <CustomTable01
                  columnsTable={columnsTableTags}
                  visibleContent={visibleTableTags}
                  dataset={itemsTableTags}
                  title="Custom tags"
                  description=""
                  pageSize={10}
                  onSelectionItem={() => {}}
                  extendedTableProperties={{ variant: "borderless" }}
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
                          <Button variant="primary" onClick={() => setVisibleShowMetadata(false)}>Close</Button>
                      </SpaceBetween>
                  </Box>
              }
              header={
                  <Header variant="h1" description="Metadata definition for the resource.">
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
