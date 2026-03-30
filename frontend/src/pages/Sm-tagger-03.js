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
        StatusIndicator
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import { createLabelFunction, customFormatNumberShort, calculateDuration } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CustomTable03 from "../components/Table03";
import CodeEditor01  from '../components/CodeEditor01';
import ParametersViewer from '../components/ParametersViewer-01';
import ProcessLogsComponent from '../components/ProcessLogs-01';



//-- Split panel
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

    //-- Get scan_id from URL parameters
    const [searchParams] = useSearchParams();
    const scanId = searchParams.get('scan_id');

    //-- Process data
    const [processData, setProcessData] = useState({});
    const [processLogs, setProcessLogs] = useState("");
    const [navigationOpen, setNavigationOpen] = useState(false);

    //-- Table columns Resources
    const columnsTableResources = [
        {id: 'action',header: 'Filtered',cell: item => (
          <StatusIndicator type={item['action'] == "1" ? "success" : item['action'] == "2" ? "error" : "pending"}>
            {item['action'] == "1" ? "Included" : item['action'] == "2" ? "Excluded" : "Unknown"}
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
              <Badge color="blue">{item['tags_number']}</Badge>
          ),ariaLabel: createLabelFunction('tags_number'),sortingField: 'tags_number',},
        {id: 'metadata',header: 'Metadata',cell: item => (
            <Badge color="green">JSON</Badge>
        ),ariaLabel: createLabelFunction('metadata'),sortingField: 'metadata',},
    ];

    const visibleContentResources = ['action', 'account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];

    //-- Pagination
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    var fetchSize = useRef(100); // Pre-fetch size (chunk size) for Table03

    //-- Filter Action
    const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Resources included', value : "1" });
    const filterAction = useRef("1");

    //-- Table key for forcing refresh
    const [tableKey, setTableKey] = useState(0);




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
                            processId : 'tagger::api-104-get-dataset-tagging'
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
            console.log('Timeout API error - PID: 08-get-dataset-tagging');
      }
    };




    //--## Get Dataset Resources (for Table03 pre-fetching)
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




    //--## JSON Pretty
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
        if (scanId) {
          getProcessData();
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
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/dashboard/"} />}
            navigationOpen={navigationOpen}
            onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
            contentType="dashboard"
            content={
                      <ContentLayout
                          defaultPadding
                          header={
                              <Header
                                variant="h1"
                                description={`Review inventory results, tagging execution metrics, and process logs for tagging process ${scanId || ''}.`}
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
                                      variant='primary'
                                    >
                                      Open Tag Explorer
                                    </Button>
                                     <Button iconName="refresh" onClick={() => {
                                                          getProcessData();
                                                          getProcessLogs();
                                    }}></Button>
                                  </SpaceBetween>
                                }
                              >
                                Tagging Process Details ({scanId})
                              </Header>
                          }
                      >
                          <Container>

                            {/* ----### Process Tabs */}
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
                                                        value: processData['scan_id'] || '-'
                                                      },
                                                      {
                                                        label: "Source",
                                                        value: processData['name'] || '-'
                                                      },
                                                      {
                                                        label: "Action",
                                                        value: (
                                                          <StatusIndicator type={processData['action'] == 1 ? "success" : processData['action'] == 2 ? "error" : "pending"}>
                                                            {processData['action'] == 1 ? "Tags added" : processData['action'] == 2 ? "Tags removed" : "Unknown"}
                                                          </StatusIndicator>
                                                        )
                                                      },
                                                      {
                                                        label: "Inventory Started",
                                                        value: processData['start_time'] || '-'
                                                      },
                                                      {
                                                        label: "Inventory Ended",
                                                        value: processData['end_time'] || '-'
                                                      },
                                                      {
                                                        label: "Inventory Duration",
                                                        value: calculateDuration(processData['start_time'], processData['end_time'])
                                                      },
                                                      {
                                                        label: "Tagging Started",
                                                        value: processData['start_time_tagging'] || '-'
                                                      },
                                                      {
                                                        label: "Tagging Ended",
                                                        value: processData['end_time_tagging'] || '-'
                                                      },
                                                      {
                                                        label: "Tagging Duration",
                                                        value: calculateDuration(processData['start_time_tagging'], processData['end_time_tagging'])
                                                      },
                                                      {
                                                        label: "Resources Tagged (Success)",
                                                        value: (
                                                          <Badge color="green">
                                                            {customFormatNumberShort(processData['resources_tagged_success'] || 0, 0)}
                                                          </Badge>
                                                        )
                                                      },
                                                      {
                                                        label: "Resources Tagged (Errors)",
                                                        value: (
                                                          <Badge color="red">
                                                            {customFormatNumberShort(processData['resources_tagged_error'] || 0, 0)}
                                                          </Badge>
                                                        )
                                                      },
                                                      {
                                                        label: "Total Resources Discovered",
                                                        value: (
                                                          <Badge color="blue">
                                                            {customFormatNumberShort(processData['resources'] || 0, 0)}
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
                                                      description={"AWS resources discovered during the inventory scan. Use filters to view included or excluded resources."}
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
                                                                          { label: "Resources included", value: "1" },
                                                                          { label: "Resources excluded", value: "2" },
                                                                        ]}
                                                                    />
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
                                                    value={processData['parameters']}
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

                          </Container>

                      </ContentLayout>

            }
          />

    </div>
  );
}

export default Application;
