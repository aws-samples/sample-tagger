import {useState,useEffect,useRef} from 'react'
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
Select,
Input,
Modal,
ButtonDropdown,
Link
} from '@cloudscape-design/components';

import '@aws-amplify/ui-react/styles.css';

import CodeEditor01  from '../components/CodeEditor01';
import CustomHeader from "../components/Header";

function Application() {

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
   
    //-- Modules
    const [moduleName, setModuleName] = useState("");
    var currentModuleName = useRef("");    
    var currentModuleId = useRef("");        
    var currentModuleContent = useRef("");  
    var beforeModuleContent = useRef("");  

        
    const [selectedModule,setSelectedModule] = useState({});
    const [moduleDataset,setModuleDataset] = useState([]); 
    const [moduleContent,setModuleContent] = useState("");      
    const [editorEventUid, setEditorEventUid] = useState(0); 


    const [visibleCreateModule, setVisibleCreateModule] = useState(false);
    const [visibleDeleteModule, setVisibleDeleteModule] = useState(false);
    const [visibleEditModule, setVisibleEditModule] = useState(false);


    //--## Create API object
    function createApiObject(object){
        const xhr = new XMLHttpRequest();
        xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
        xhr.setRequestHeader("Authorization",`Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
        xhr.setRequestHeader("Content-Type","application/json");            
        return xhr;
    }



    //--## Gather Modules
    async function gatherModules(moduleSelected){
      try {
            
            var parameters = {                         
                            processId : "17-get-list-modules"
            };        
    
            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    

                          var response = JSON.parse(api.responseText)?.['response'];   

                          const modules = response['modules'].sort((a, b) => 
                              a.name.localeCompare(b.name)
                          );

                          var items = [];
                          modules.forEach(element => {
                              items.push({ 
                                            label: element['name'], 
                                            value: element['name'], 
                                            iconName: "file",
                                            description: "Size",
                                            tags: [String(element['size'])],
                                            labelTag: String(element['lastModified']),
                              });
                          });            
                          
                          
                       
                          var selectedItem = findElementByLabel(items, moduleSelected);

                          if ( items.length > 0 ){
                              if (selectedItem == null){
                                currentModuleId.current = items[0]['value'];
                                currentModuleName.current = items[0]['value'];
                                setSelectedModule(items[0]);
                                setModuleDataset(items); 
                                getFileContent(items[0]['value']);
                              }
                              else{
                                currentModuleId.current = selectedItem['value'];
                                currentModuleName.current = selectedItem['value'];
                                setSelectedModule(selectedItem);
                                setModuleDataset(items); 
                                getFileContent(selectedItem['value']);                                
                              }                            
                          }                        
                         
                        
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));  

       
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 17-get-list-modules');                  
      }
    };


    //--## Get file content
    async function getFileContent(fileName){
      try {
            
            var parameters = {                         
                            processId : "18-get-module-content",
                            fileName : fileName
            };        
            
            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = function() {                    
                      if (api.status === 200) {    

                          var response = JSON.parse(api.responseText)?.['response'];   
                          currentModuleContent.current = response['content'];
                          setModuleContent(currentModuleContent.current);
                        
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));  

       
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 18-get-file-content');                  
      }
    };


    //--## Update Module
    async function handleClickSaveModule(fileName, content){
      try {
            
            var parameters = {                         
                            processId : "19-save-module-content",
                            fileName : fileName,
                            content : content
            };        


            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = async function() {                    
                      if (api.status === 200) {    
                          
                          var response = JSON.parse(api.responseText)?.['response'];                                                                                
                          await gatherModules(fileName);
              
                          setApplicationMessage([
                                                  {
                                                    type: "success",
                                                    content: "Module has been saved successfully.",
                                                    dismissible: true,
                                                    dismissLabel: "Dismiss message",
                                                    onDismiss: () => setApplicationMessage([]),
                                                    id: "message_1"
                                                  }
                          ]);
                          
                          
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));              
            
            
      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 19-save-module-content');                  
      }
    };


    //--## Delete Module
    async function handleClickDeleteModule(){
      try {
            
            var parameters = {                         
                            processId : "20-delete-module-content",
                            fileName : currentModuleId.current,
            };        
    
            const api = createApiObject({ method : 'POST', async : true });          
            api.onload = async function() {                    
                      if (api.status === 200) {    
                        await gatherModules(null);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));  

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 20-delete-module-content');                  
      }
    };

  
    function findElementByLabel(arr, searchLabel) {
      return arr.find(element => element.label === searchLabel) || null;
    }

    
    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherModules(null);
    }, []);
    
    
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
                          <Header variant="h1" description="Manage modules used by tagging and search process.">
                              Module Management  
                          </Header>
                          <br/>
                          <Container>
                            <table style={{"width":"100%"}}>
                                <tr>  
                                    <td valign="middle" style={{"width":"35%", "padding-right": "2em", "text-align": "center"}}>  
                                      <FormField label={"Module"}>
                                          <Select
                                                    disabled={visibleEditModule}
                                                    selectedOption={selectedModule}
                                                    onChange={({ detail }) => {
                                                      currentModuleId.current = detail.selectedOption['value'];
                                                      currentModuleName.current = detail.selectedOption['label'];
                                                      setSelectedModule(detail.selectedOption);         
                                                      getFileContent(detail.selectedOption['label']);                                                                                                
                                                    }}
                                                    options={moduleDataset}
                                                    filteringType="auto"
                                                    triggerVariant="option"
                                          />
                                      </FormField>
                                    </td>
                                    <td valign="middle" style={{"width":"30%", "padding-right": "2em", "text-align": "center"}}>  
                                          
                                    </td>
                                    <td valign="middle" style={{"width":"35%", "padding-right": "2em", "text-align": "center"}}>  
                                            <Box float="right">
                                              <SpaceBetween direction="horizontal" size="xs">
                                                
                                              <Button 
                                                    iconName="refresh" 
                                                    disabled={visibleEditModule}
                                                    onClick={() => { 
                                                      gatherModules(null);
                                                    }}>

                                                </Button>
                                                <Button external={false}                                                        
                                                        iconAlign="right"
                                                        iconName="external"
                                                        target="_blank"
                                                        href={"/modules/validation?mtid=" + currentModuleId.current}                                                        
                                                >
                                                  Validate module
                                                </Button>  
                                                <ButtonDropdown
                                                  disabled={visibleEditModule}
                                                  variant={"primary"}
                                                  items={[
                                                    { text: "Create", id: "create"},
                                                    { text: "Edit", id: "edit"},
                                                    { text: "Delete", id: "delete" }
                                                  ]}
                                                  onItemClick={( item ) => { 

                                                      switch(item.detail.id){
                                                          case "create":
                                                            setVisibleCreateModule(true);
                                                            setModuleName("");                                                          
                                                            break;
                                                          
                                                          case "edit":
                                                            beforeModuleContent.current = currentModuleContent.current;
                                                            setVisibleEditModule(true);
                                                            break;
                                                          
                                                          case "delete":
                                                            setVisibleDeleteModule(true);
                                                            break;

                                                      }
                                                        
                                                    }
                                                  }
                                                >
                                                  Action
                                                </ButtonDropdown>
                                                                                         
                                                
                                              </SpaceBetween>

                                            </Box>
                                    </td>
                                </tr>
                            </table>                                 
                            <br/>    
                            <table style={{"width":"100%"}}>
                                <tr>  
                                    <td valign="middle" style={{"width":"50%", "padding-right": "2em", "text-align": "center"}}>  
                                            
                                            <CodeEditor01
                                                    key={editorEventUid}
                                                    format={"python"}
                                                    value={currentModuleContent.current}
                                                    readOnly={!visibleEditModule}
                                                    height={750}
                                                    header={
                                                              <Header
                                                                variant="h4"
                                                              >
                                                                Module editor
                                                              </Header>
                                                            }
                                                      onChange={ ( item ) => { currentModuleContent.current = item; } }
                                            />
                                                  { visibleEditModule &&
                                                  <div>
                                                      <br/>
                                                      <Box float="right">
                                                        <SpaceBetween direction="horizontal" size="xs">
                                                            <Button variant="link"  
                                                                      onClick={() => { 
                                                                        currentModuleContent.current = beforeModuleContent.current;                                                                        
                                                                        setVisibleEditModule(false);                                                                                 
                                                                        setEditorEventUid(prevEventUid => prevEventUid + 1);                                                          
                                                                        }}
                                                              >
                                                                  Cancel
                                                              </Button>
                                                              <Button variant="primary" 
                                                                  onClick={() => {                       
                                                                                  handleClickSaveModule(currentModuleId.current, currentModuleContent.current);            
                                                                                  setVisibleEditModule(false);                                                                  
                                                                              }}
                                                              >
                                                                Save
                                                              </Button>
                                                        </SpaceBetween>
                                                      </Box>
                                                  </div>

                                                  }
                                                

                                      </td>
                                </tr>
                                
                            </table>
                          </Container>
                          
                  </div>
                
            }
          />
        
          <Modal
            onDismiss={() => setVisibleCreateModule(false)}
            visible={visibleCreateModule}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                  <Button variant="link"  
                          onClick={() => { 
                                    setVisibleCreateModule(false);
                                }}
                  >
                      Cancel
                  </Button>
                  <Button variant="primary" 
                      onClick={() => { 
                                     
                                      handleClickSaveModule(moduleName, "");                                           
                                      setVisibleCreateModule(false);
                                  }}
                  >
                    Create
                  </Button>
                </SpaceBetween>
              </Box>
            }
            header="Create module"
          >
            <FormField
              label="Name"
              description="Provide the name for the module, this name should be same as boto3 APIs service naming convention (ex. ec2, rds, s3, elb)."

            >

              <Link
                external
                href="https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/index.html"
                variant="primary"
              >
                Learn more
              </Link>
              <br/>             
              <br/>             
              <Input 
                  value={moduleName}
                  onChange={({ detail }) => {
                       setModuleName(detail.value);
                       currentModuleName.current = detail.value;
                  }
                }
              />
            </FormField>
          </Modal>


            
          <Modal
            onDismiss={() => setVisibleDeleteModule(false)}
            visible={visibleDeleteModule}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="link"  
                              onClick={() => { 
                                setVisibleDeleteModule(false);
                                    }}
                      >
                          Cancel
                      </Button>
                      <Button variant="primary" 
                          onClick={() => {                                          
                                          handleClickDeleteModule();
                                          setVisibleDeleteModule(false);
                                      }}
                      >
                        Delete
                      </Button>
                </SpaceBetween>
              </Box>
            }
            header="Delete module"
          >
            Do you want to delete module [{currentModuleId.current}] ?
          </Modal>
        
    </div>
  );
}

export default Application;
