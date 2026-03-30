import {useState,useEffect,useRef, useCallback} from 'react'

//--## CloudScape components
import {
        AppLayout,
        SideNavigation,
        ContentLayout,
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
        Link,
        Container,
        SplitPanel,
        Tabs,
        Badge,
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
import CustomTable03 from "../components/Table03";
import TokenGroupReadOnly01 from '../components/TokenGroupReadOnly01';
import WhereClauseViewer01 from '../components/WhereClauseViewer01';
import CodeEditor01 from '../components/CodeEditor01';
import ParametersViewer from '../components/ParametersViewer-01';
import ProcessLogsComponent from '../components/ProcessLogs-01';
import AccountEditorComponent from '../components/AccountEditor-01';
import RegionEditorComponent from '../components/RegionEditor-01';
import ServiceEditorComponent from '../components/ServiceEditor-01';
import WhereClauseBuilder01 from '../components/WhereClauseBuilder01';



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

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);

    //-- Navigation
    const [navigationOpen, setNavigationOpen] = useState(false);

    //-- Customize mode for create modal
    const [customizeMode, setCustomizeMode] = useState(false);

    //-- Split panel
    const [splitPanelShow, setSplitPanelShow] = useState(false);
    const [splitPanelSize, setSplitPanelSize] = useState(350);

    //-- Process data for split panel
    const [processLogs, setProcessLogs] = useState("");

    //-- Selected scanning process
    var currentScanId = useRef({});
    const [isSelectMetadataBase, setIsSelectMetadataBase] = useState(false);

    //-- Resources table columns
    const columnsTableResources = [
        {id: 'account',header: 'Account',cell: item => item['account'],ariaLabel: createLabelFunction('account'),sortingField: 'account'},
        {id: 'region',header: 'Region',cell: item => item['region'],ariaLabel: createLabelFunction('region'),sortingField: 'region'},
        {id: 'service',header: 'Service',cell: item => item['service'],ariaLabel: createLabelFunction('service'),sortingField: 'service'},
        {id: 'type',header: 'Type',cell: item => item['type'],ariaLabel: createLabelFunction('type'),sortingField: 'type'},
        {id: 'identifier',header: 'Identifier',cell: item => item['identifier'],ariaLabel: createLabelFunction('identifier'),sortingField: 'identifier'},
        {id: 'name',header: 'Name',cell: item => item['name'],ariaLabel: createLabelFunction('name'),sortingField: 'name'},
        {id: 'tags_number',header: 'Tags',cell: item => (
              <a href='#;' style={{ "textDecoration": "none", "color": "inherit" }} onClick={() => showTags(item)}>
                  <Badge color="blue">{item['tags_number']}</Badge>
              </a>
          ),ariaLabel: createLabelFunction('tags_number'),sortingField: 'tags_number'},
        {id: 'metadata',header: 'Metadata',cell: item => (
              <a href='#;' style={{ "textDecoration": "none", "color": "inherit" }} onClick={() => showMetadata(item)}>
                  <Badge color="green">JSON</Badge>
              </a>
          ),ariaLabel: createLabelFunction('metadata'),sortingField: 'metadata'},
    ];
    const visibleContentResources = ['account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];


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

    //-- Pagination refs
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    var fetchSize = useRef(100);
    const [tableKey, setTableKey] = useState(0);

    //-- Process table columns
    const columnsTableProcess = [
          {id: 'scan_id',header: 'Identifier',cell: item => (
                <Link href={"/metadata/explorer/?scan_id=" + item['scan_id']} variant="primary" external>
                  {item['scan_id']}
                </Link>
              )  ,ariaLabel: createLabelFunction('scan_id'),sortingField: 'scan_id',},
          {id: 'status',header: 'Status',cell: item => (
            <StatusIndicator type={item['status'] == "completed" ? "success" : (item['status'] == "in-progress" ? "in-progress" : "error")}>
              {item['status'] == "completed" ? "Available" : (item['status'] == "in-progress" ? "In-Progress" : "Unknown")}
            </StatusIndicator>
          ),ariaLabel: createLabelFunction('action'),sortingField: 'action',},
          {id: 'name',header: 'Name',cell: item => item.name,ariaLabel: createLabelFunction('name'),sortingField: 'name',},
          {id: 'start_time',header: 'Creation time',cell: item => item.start_time,ariaLabel: createLabelFunction('start_time'),sortingField: 'start_time',},
          {id: 'end_time',header: 'Completed time',cell: item => item.end_time,ariaLabel: createLabelFunction('end_time'),sortingField: 'end_time',},
          {id: 'duration',header: 'Duration',cell: item => calculateDuration(item.start_time, item.end_time),ariaLabel: createLabelFunction('duration'),sortingField: 'duration',},
          {id: 'resources',header: 'Resources',cell: item => customFormatNumberShort(item.resources,0),ariaLabel: createLabelFunction('resources'),sortingField: 'resources',},
    ];
    const visibleTableProcess = ['scan_id', 'name', 'status', 'start_time', 'end_time',  'resources', 'duration' ];
    const [itemsTableProcess,setItemsTableProcess] = useState([]);


    //-- Create Metadatabase Options
    const [selectedAccounts,setSelectedAccounts] = useState([]);
    const [selectedRegions,setSelectedRegions] = useState([]);
    const [selectedServices,setSelectedServices] = useState([]);
    const [selectedFilterText,setSelectedFilterText] = useState("");

    const accountList = useRef([]);
    const regionList = useRef([]);
    const serviceList = useRef([]);
    const filterListText = useRef("");

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
        xhr.setRequestHeader("Content-Type","application/json");
        return xhr;
    }




    //--## Refresh Parameters
    function refreshParameters(parameters){
          var accounts = [];
          parameters['accounts'].forEach( element => {
            accounts.push({ label: element, value: element });
          });
          setSelectedAccounts(accounts);
          accountList.current = accounts;

          var regions = [];
          parameters['regions'].forEach( element => {
            regions.push({ label: element, value: element });
          });
          setSelectedRegions(regions);
          regionList.current = regions;

          var services = [];
          parameters['services'].forEach( element => {
            services.push({ label: element, value: element });
          });
          setSelectedServices(services);
          serviceList.current = services;

          setSelectedFilterText(parameters['filter']);
          filterListText.current = parameters['filter'];
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
                  type : 2
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
        var mtBaseName = "metadatase-base-" + Math.random().toString(36).substring(2,12);
        currentMetadataBaseName.current = mtBaseName;
        setMetadataBaseName(mtBaseName);
        setCustomizeMode(false);
        gatherProfiles();
        setVisibleCreateMetadataBase(true);
    }




    //--## Fetch Resources for Split Panel
    async function fetchDatasetResources({ page, limit }){
      return new Promise((resolve, reject) => {
            try {
                  var parameters = {
                                  processId : 'metadata::api-001-get-metadata-results',
                                  scanId : currentScanId.current['scan_id'],
                                  action : "1",
                                  page : page,
                                  limit : limit
                  };

                  const api = createApiObject({ method : 'POST', async : true });
                  api.onload = function() {
                            if (api.status === 200) {
                                var response = JSON.parse(api.responseText)?.['response'];
                                totalRecords.current = response['records'];
                                resolve({
                                      resources: response['resources'],
                                      totalRecords: response['records'],
                                      pages: response['pages']
                                });
                            } else {
                                reject(new Error('API error'));
                            }
                  };
                  api.onerror = function() {
                        reject(new Error('Network error'));
                  };
                  api.send(JSON.stringify({ parameters : parameters }));
            }
            catch(err){
                  console.log(err);
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




    //--## JSON Pretty
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
                ruleset['filter'] = filterListText.current;

                var parameters = {
                                processId : 'metadata::api-002-create-metadata-search',
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
                                processId : 'metadata::api-008-delete-metadata-base',
                                scanId : currentScanId.current['scan_id']
                };

                const api = createApiObject({ method : 'POST', async : true });
                api.onload = function() {
                          if (api.status === 200) {
                              var response = JSON.parse(api.responseText)?.['response'];
                              currentScanId.current = {};
                              setIsSelectMetadataBase(false);
                              setSplitPanelShow(false);
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



    //--## Rendering
    return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/metadata/bases/"} />}
            navigationOpen={navigationOpen}
            onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
            disableContentPaddings={true}
            contentType="table"
            toolsHide={true}
            splitPanelOpen={splitPanelShow}
            onSplitPanelToggle={() => setSplitPanelShow(!splitPanelShow)}
            onSplitPanelResize={({ detail: { size } }) => { setSplitPanelSize(size); }}
            splitPanelSize={splitPanelSize}
            splitPanel={
                      <SplitPanel
                          header={
                                <div>
                                { currentScanId.current['scan_id'] &&
                                  <Header
                                      variant="h3"
                                      actions={
                                        <SpaceBetween direction="horizontal" size="xs">                                      
                                          <Button
                                            iconName="external"
                                            iconAlign="right"
                                            href={"/metadata/process/?scan_id=" + currentScanId.current['scan_id']}
                                            target="_blank"
                                            ariaLabel="View details"
                                            variant='primary'
                                          >
                                            Open details
                                          </Button>
                                        </SpaceBetween>
                                      }
                                  >
                                      {"Metadata Base : " + (currentScanId.current['name'] || currentScanId.current['scan_id']) }
                                  </Header>
                                }
                                </div>
                          }
                          i18nStrings={splitPanelI18nStrings}
                          closeBehavior="collapse"
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
                                                    label: "Name",
                                                    value: currentScanId.current['name'] || '-'
                                                  },
                                                  {
                                                    label: "Status",
                                                    value: (
                                                      <StatusIndicator type={currentScanId.current['status'] == "completed" ? "success" : (currentScanId.current['status'] == "in-progress" ? "in-progress" : "error")}>
                                                        {currentScanId.current['status'] == "completed" ? "Available" : (currentScanId.current['status'] == "in-progress" ? "In-Progress" : "Unknown")}
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
                                                  title={"Discovered Resources"}
                                                  description={"Resources captured in this metadata baseline."}
                                                  fetchSize={fetchSize.current}
                                                  displayPageSize={pageSize.current}
                                                  totalRecords={totalRecords.current}
                                                  onFetchData={fetchDatasetResources}
                                                  selectionType="single"
                                                  tableActions={
                                                    <SpaceBetween direction="horizontal" size="xs">
                                                      <Button iconName="refresh" onClick={() => { setTableKey(prev => prev + 1); }} />
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
                                              variant="footer"
                                            />
                                        </div>
                              }
                            ]}
                          />
                      </SplitPanel>
            }
            content={
                      <ContentLayout
                          defaultPadding
                          header={
                              <Header
                                variant="h1"
                                description="Build a tag inventory baseline from your AWS resources to power the Tag Explorer and gain visibility into how tags are applied across your environment."
                              >
                                Metadata Bases
                              </Header>
                          }
                      >
                          <Flashbar items={applicationMessage} />
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
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Build a Tag Inventory</span>
                                        </div>
                                        <br/>
                                        <SpaceBetween size="s">
                                          <div>
                                            <strong>Resource Discovery:</strong> Scan your AWS accounts and regions to capture resource metadata and tag assignments, creating a centralized baseline for tag analysis.
                                          </div>
                                        </SpaceBetween>
                                        <br/>
                                        <Button variant='primary'
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
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Explore Tag Distribution</span>
                                        </div>
                                        <p>Open the Tag Explorer to visualize tag key-value distribution across resources, identify untagged or inconsistently tagged assets, and drill down by service, account, or region.</p>
                                    </td>
                                    <td style={{"width":"33%", "padding-right": "2em", "text-align": "left", "vertical-align" : "top"}}>
                                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                          <Icon name={"settings"} size="medium" />
                                          <span style={{ marginLeft: '8px', fontSize: '16px', fontWeight: 'bold' }}>Drive Tagging Compliance</span>
                                        </div>
                                        <p>Use metadata baselines to feed compliance assessments, track tagging coverage over time, and support remediation workflows to ensure resources meet your organization's tagging standards.</p>
                                    </td>
                                </tr>
                            </table>
                          </ExpandableSection>
                          <br/>
                          {/* ----### Metadata Bases Table */}
                          <CustomTable01
                              columnsTable={columnsTableProcess}
                              visibleContent={visibleTableProcess}
                              dataset={itemsTableProcess}
                              title={"Metadata Bases"}
                              description={"View and manage your tag inventory baselines. Select a baseline to open the Tag Explorer or manage its lifecycle."}
                              pageSize={10}
                              onSelectionItem={( item ) => {
                                  currentScanId.current = item[0];
                                  setIsSelectMetadataBase(true);
                                  setSplitPanelShow(true);
                                  setTableKey(prev => prev + 1);
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
                                                 <Button external={false}
                                                        disabled={!isSelectMetadataBase}
                                                        iconAlign="right"
                                                        iconName="external"
                                                        target="_blank"
                                                        href={"/metadata/explorer/?scan_id=" + currentScanId.current['scan_id']}
                                                        variant="primary"
                                                >
                                                  Open Tag Explorer
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
                      </ContentLayout>
            }
          />

          {/* ----### Create Metadata Base Modal */}
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
                          description={"Configure the metadata baseline by providing a name and selecting a profile that defines the discovery scope."}
                        >
                          Create Metadata Base
                        </Header>
                }
              >
                  <table style={{"width":"100%"}}>
                    <tr>
                        <td valign="bottom" style={{"width":"25%", "padding-right": "2em"}}>
                          <FormField
                              label="Name"
                              description="Provide a descriptive name to identify this metadata baseline."
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
                          <FormField label={"Profiles"} description="Select the profile that defines accounts, regions, services, and filters for this baseline.">
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
                            <Header variant="h2" description="AWS account IDs included in the discovery scope for this baseline.">
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
                            <Header variant="h2" description="AWS regions where resource discovery will be performed.">
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
                                  <Header variant="h2" description="AWS services and resource types targeted for discovery.">
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

                  {/* ----### Filter */}
                  <Container
                        header={
                                <Header variant="h2" description="Conditions applied to narrow down discovered resources.">
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

            {/* ----### Delete Metadata Base Modal */}
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
            Are you sure you want to delete metadata base <b>[{currentScanId.current['name']} - {currentScanId.current['scan_id']}]</b>? This action cannot be undone.
          </Modal>

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
