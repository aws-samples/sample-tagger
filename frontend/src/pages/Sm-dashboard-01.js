import {useState,useEffect,useRef} from 'react'
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import {  createLabelFunction, customFormatNumberShort } from '../components/Functions';

import {
AppLayout ,
SideNavigation,
SpaceBetween,
Button,
Header,
Box,
Container,
SplitPanel,
Tabs ,
Select, 
Modal ,
Icon ,
Badge 
} from '@cloudscape-design/components';

import '@aws-amplify/ui-react/styles.css';

import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";
import CustomTable02 from "../components/Table02";
import NativeChartBar01 from '../components/NativeChartBar-01';
import CodeEditor01  from '../components/CodeEditor01';

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


function Application() {
    
    
    //-- Variable for split panels
    const [splitPanelShow,setsplitPanelShow] = useState(false);
    const [splitPanelSize, setSplitPanelSize] = useState(500);
    

    //-- Charts
    const [chartSummaryResources, setChartSummaryResources] = useState({ added : [], removed : []});
    const [chartSummaryServices, setChartSummaryServices] = useState([]);


    //-- Variables table
    const columnsTableProcess = [
                  {id: 'scan_id',header: 'ProcessId',cell: item => item.scan_id,ariaLabel: createLabelFunction('scan_id'),sortingField: 'scan_id',},
                  {id: 'action',header: 'Action',cell: item => ( 
                    <div style={{"text-align" : "left"}}>                                                                                      
                        <Icon name={( item['action'] == 1 ? "status-positive" : ( item['action'] == 2 ? "status-negative" : "status-pending" )  )}  />
                        &nbsp; { ( item['action'] == 1 ? "Added" : ( item['action'] == 2 ? "Removed" : "Unknown" ) ) }
                    </div> )  ,ariaLabel: createLabelFunction('action'),sortingField: 'action',},                                 
                  {id: 'start_time',header: 'Inventory Start',cell: item => item.start_time,ariaLabel: createLabelFunction('start_time'),sortingField: 'start_time',},
                  {id: 'end_time',header: 'Inventory End',cell: item => item.end_time,ariaLabel: createLabelFunction('end_time'),sortingField: 'end_time',},
                  {id: 'start_time_tagging',header: 'Tagging Start',cell: item => item.start_time_tagging,ariaLabel: createLabelFunction('start_time_tagging'),sortingField: 'start_time_tagging',},
                  {id: 'end_time_tagging',header: 'Tagging End',cell: item => item.end_time_tagging,ariaLabel: createLabelFunction('end_time_tagging'),sortingField: 'end_time_tagging',},                  
                  {id: 'resources_tagged_success',header: 'Success',cell: item => customFormatNumberShort(item.resources_tagged_success,0),ariaLabel: createLabelFunction('resources_tagged_success'),sortingField: 'resources_tagged_success',},
                  {id: 'resources_tagged_error',header: 'Errors',cell: item => customFormatNumberShort(item.resources_tagged_error,0),ariaLabel: createLabelFunction('resources_tagged_error'),sortingField: 'resources_tagged_error',},                
    ];
    const visibleTableProcess = ['scan_id', 'action', 'start_time', 'start_time_tagging',  'resources_tagged_success', 'resources_tagged_error'];
    const [itemsTableProcess,setItemsTableProcess] = useState([]);
    
    
    // Table variables Workload
    const columnsTableResources = [
        {id: 'action',header: 'Filtered',cell: item => ( 
          <div style={{"text-align" : "left"}}>                                                                                      
              <Icon name={( item['action'] == "1" ? "status-positive" : ( item['action'] == "2" ? "status-negative" : "status-pending" )  )}  />
              &nbsp; { ( item['action'] == "1" ? "Filter-In" : ( item['action'] == "2" ? "Filter-Out" : "Unknown" ) ) }
          </div> )  ,ariaLabel: createLabelFunction('action'),sortingField: 'action',},      
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

    //-- Pagging    
    const pageId = useRef(0);
    var totalPages = useRef(1);
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    
    

    //-- Filter Action
    const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Filter-In', value : "1" });
    const filterAction = useRef("1");


    var currentScanId = useRef({ parameters : {} });

        
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


    //--## Create API object
    function createApiObject(object){
      const xhr = new XMLHttpRequest();
      xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
      xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
      xhr.setRequestHeader("Content-Type","application/json");            
      return xhr;
    }



    //--## Get Dataset Tagging
    async function getDatasetTagging(){
      try {
          
            var parameters = {                         
                            processId : "08-get-dataset-tagging"           
            };        
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                      
                          setItemsTableProcess(response['processes']);  
                          setChartSummaryResources(response['summary']);     
                          setChartSummaryServices(response['services'])                                   
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 08-get-dataset-tagging');                  
      }
    };



    //--## Get Dataset Resources
    async function getDatasetResources(){
      try {
          
            var parameters = {                         
                      processId : "01-get-metadata-results", 
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



    
    //##-- Function to format JSON
    function JSONPretty(obj) {      
      try {     
            return JSON.stringify(JSON.parse(obj),null,4);        
      } catch (error) {        
        return "";
      }
    }

    
    
    
    //##-- Function to Convert to CSV
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



    //##-- Function to export table to CSV
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

    
    //-- Init Function
    // eslint-disable-next-line
    useEffect(() => {
        getDatasetTagging();        
    }, []);
    
   
    
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
                          
                              <Header variant="h3">
                                     {"Process Identifier : " + currentScanId.current['scan_id'] }
                              </Header>
                            
                          } 
                          i18nStrings={splitPanelI18nStrings} closeBehavior="hide"
                          onSplitPanelToggle={({ detail }) => {
                                         
                                        }
                                      }
                      >
                        <Tabs
                            tabs={[
                              {
                                label: "Resources",
                                id: "first",
                                content: 
                                        <div>
                                            <Container>
                                              <CustomTable02
                                                  columnsTable={columnsTableResources}
                                                  visibleContent={visibleContentResources}
                                                  dataset={datasetResources}
                                                  title={"Resource search results"}
                                                  description={""}                                                  
                                                  onSelectionItem={( item ) => {                                                                                    
                                                      //resourceId.current = item[0];                                                
                                                    }
                                                  }
                                                  pageSize={pageSize.current}
                                                  totalPages={totalPages.current}
                                                  totalRecords={totalRecords.current}
                                                  pageId={pageId.current + 1}
                                                  onPaginationChange={( item ) => {                                                                                                                                        
                                                      pageId.current = item - 1;       
                                                      getDatasetResources();                                        
                                                    }
                                                  }
                                                  extendedTableProperties = {
                                                      { 
                                                          variant : "borderless",                                                         
                                                  }                                                
                                                  }
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
                                                                        getDatasetResources();
                                                                      }
                                                                    }
                                                                    options={[
                                                                      { label: "Filter-In", value: "1" },
                                                                      { label: "Filter-Out", value: "2" },
                                                                      { label: "All", value: "3" }                                                                
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
                                              <CodeEditor01
                                                format={"json"}
                                                value={JSONPretty(currentScanId.current['parameters'])}
                                                readOnly={true}
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
                          <Container
                            header={
                                      <Header
                                        variant="h2"
                                        actions={
                                          <SpaceBetween
                                            direction="horizontal"
                                            size="xs"
                                          >
                                            <Button iconName="refresh" onClick={() => { 
                                                                  getDatasetTagging();
                                            }}></Button>
                                            <Button variant={"primary"} href="/tagger/"
                                            >
                                              Launch tagging process
                                            </Button>                                            
                                          </SpaceBetween>
                                        }
                                      >
                                        Tagging execution summary
                                      </Header>
                                    }
                          >
                          
                            <table style={{"width":"100%"}}>
                                <tr>  
                                    <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>  
                                          <NativeChartBar01 
                                              title={"Total resources by tag action"}
                                              extendedProperties = {
                                                  { hideFilter : true } 
                                              }
                                              height={"250"}
                                              series={[
                                                        {
                                                          title: "Added",
                                                          type: "bar",
                                                          data: chartSummaryResources['added']
                                                        },                                                  
                                                        {
                                                          title: "Removed",
                                                          type: "bar",
                                                          data: chartSummaryResources['removed']
                                                        },
                                                      ]}
                                          />      
                                    </td>
                                    <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>  
                                          <NativeChartBar01 
                                              title={"Total resources by service type"}
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
                          <CustomTable01
                              columnsTable={columnsTableProcess}
                              visibleContent={visibleTableProcess}
                              dataset={itemsTableProcess}
                              title={"Tagging Processes"}
                              description={""}
                              pageSize={10}
                              onSelectionItem={( item ) => {
                                  currentScanId.current = item[0];                                                                    
                                  setsplitPanelShow(true);
                                  pageId.current = 0;
                                  getDatasetResources();
                                }
                              }
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



    </div>
  );
}

export default Application;
