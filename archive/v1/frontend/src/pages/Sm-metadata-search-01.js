import {useState,useEffect,useRef, useCallback} from 'react'
import { useSearchParams } from 'react-router-dom';
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";

import {
  AppLayout,
  SideNavigation,
  Flashbar,
  Header,
  Box,
  Container,
  ExpandableSection,
  Icon,
  SpaceBetween,
  Button,
  ButtonDropdown,
  Link,
  Badge,
  Modal,
  KeyValuePairs,
  StatusIndicator
} from '@cloudscape-design/components';

import { createLabelFunction, customFormatNumberShort } from '../components/Functions';

import CodeEditor01  from '../components/CodeEditor01';
import WhereClauseBuilder01 from '../components/WhereClauseBuilder01';


function Application() {


  
    //--## Get Parameters
    const [params]=useSearchParams();   
    const metadataIdentifier=params.get("mtid");  
  

    const [sqlWhereClause, setSqlWhereClause] = useState('');  


    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);   
    
    //var currentConditional = useRef("POSITION('subnet-03bff4b2b43b0d393' in metadata) > 0");
    var currentConditional = useRef("");
  

    // Table variables Workload
    const columnsTableResources = [
        //{id: 'account',header: 'Account',cell: item => "1234567890",ariaLabel: createLabelFunction('account'),sortingField: 'account',},
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

    const visibleContentResources = ['account', 'region', 'service', 'type', 'identifier', 'name', 'tags_number', 'metadata'];
    const [datasetResources,setDatasetResources] = useState([]);

    // Metadata Information
    const [datasetMetadataInformation,setDatasetMetadataInformation] = useState([]);

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



    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
        xhr.setRequestHeader("Content-Type","application/json");            
        return xhr;
    }


    //--## Handle WhereClause change
    const handleWhereClauseChange = useCallback((newValue) => {    
      setSqlWhereClause(newValue);    
      currentConditional.current = newValue;    
    }, []);



    //--## Get Metadata Information
    async function getMetadataInformation(){
      try {          

            setDatasetResources([]);
            var parameters = {                         
              processId : "15-get-dataset-metadata-information", 
              scanId : metadataIdentifier             
            };       
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                      
                          setDatasetMetadataInformation(response['processes']);                          
                          
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 15-get-dataset-metadata-information');                  
      }
    };

    //--## Get Metadata Resources
    async function getMetadataResources(){
      try {          

            setDatasetResources([]);
            var parameters = {                         
              processId : "14-get-metadata-search", 
              scanId : metadataIdentifier,   
              filter : currentConditional.current
            };       
            

            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    
                          var response = JSON.parse(api.responseText)?.['response'];                                          
                          setDatasetResources(response['resources']);                          
                          
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 13-get-dataset-metadata-bases');                  
      }
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



    //--## Function to export table to CSV
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

    
    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        getMetadataInformation();
        getMetadataResources();
    }, []);
    
  return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout            
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/search/"} />}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <div style={{"padding" : "1em"}}>
                          <Flashbar items={applicationMessage} />                          
                          <Header variant="h1">
                              Metadata Search ({metadataIdentifier})
                          </Header>
                          <br/>
                          <KeyValuePairs
                              columns={4}
                              items={[
                                 {
                                  label: "Name",
                                  value: datasetMetadataInformation['name']
                                },  
                                {
                                  label: "Status",
                                  value: (
                                          datasetMetadataInformation['status'] == "completed" ?  <StatusIndicator>Available</StatusIndicator> :  <StatusIndicator>In-progress</StatusIndicator> 
                                  )
                                },                                
                                {
                                  label: "Creation time",
                                  value: datasetMetadataInformation['start_time']
                                },                                 
                                {
                                  label: "Resources",
                                  value: datasetMetadataInformation['resources']
                                },
                              ]}
                            />            
                          <br/>
                          <Container
                                header={
                                        <Header variant="h1" description="Write conditions to filter resources">
                                            Filter editor
                                        </Header>
                              }
                          >
                                <WhereClauseBuilder01
                                  onChange={handleWhereClauseChange} 
                                  value={sqlWhereClause} 
                                  readOnly={false}
                                />
                                <Box float="right">
                                  <SpaceBetween direction="horizontal" size="xs">
                                        <Button variant="primary" 
                                                      onClick={() => { 
                                                        getMetadataResources();
                                                    }}
                                        >
                                            Search
                                        </Button>                                             
                                  </SpaceBetween>
                                </Box>
                                <br/>

                          </Container>                            
                          <br/>                             
                          <Container>
                              <CustomTable01
                                  columnsTable={columnsTableResources}
                                  visibleContent={visibleContentResources}
                                  dataset={datasetResources}
                                  title={"Resources search results"}
                                  description={""}
                                  pageSize={10}
                                  onSelectionItem={( item ) => {                                                                                    
                                      //resourceId.current = item[0];                                                
                                    }
                                  }
                                  extendedTableProperties = {
                                      { 
                                          variant : "borderless",
                                          loading : (""=="in-progress" ? true : false )

                                  }                                                
                                  }
                                  tableActions={
                                              <SpaceBetween
                                                direction="horizontal"
                                                size="xs"
                                              >
                                                <Button iconName="refresh" onClick={() => { 
                                                        //getScanResults();
                                                }}></Button>      
                                                <Button 
                                                        onClick={() => { 
                                                          const datasetExport = datasetResources.map(({ metadata, ...rest }) => rest);
                                                          exportDataToCsv(datasetExport,"resources");
                                                        }}
                                                >
                                                  Export resources to CSV
                                                </Button>                                         

                                              </SpaceBetween>
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
                readOnly={false}
              />          
          </Modal>


    </div>
  );
}

export default Application;
