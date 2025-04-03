import {useState,useEffect} from 'react'

import { applicationVersionUpdate } from '../components/Functions';
import Flashbar from "@cloudscape-design/components/flashbar";
import CustomHeader from "../components/Header";
import ContentLayout from '@cloudscape-design/components/content-layout';
import { configuration } from './Configs';

import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Box from "@cloudscape-design/components/box";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Badge from "@cloudscape-design/components/badge";
import AppLayout from '@cloudscape-design/components/app-layout';
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import architecturePublic from '../img/architecture-public.png'; 
import architecturePrivate from '../img/architecture-private.png'; 





import '@aws-amplify/ui-react/styles.css';


function Home() {
  
  //-- Application version
  const [versionMessage, setVersionMessage] = useState([]);
  const [value, setValue] = useState("public");
  const [selectedId, setSelectedId] = useState("public");
  
  //-- Call API to app version
   async function gatherVersion (){

        //-- Application update
        var appVersionObject = await applicationVersionUpdate({ codeId : "dbwcmp", moduleId: "home"} );
        
        if (appVersionObject.release > configuration["apps-settings"]["release"] ){
          setVersionMessage([
                              {
                                type: "info",
                                content: "New Application version is available, new features and modules will improve application capabilities and user experience.",
                                dismissible: true,
                                dismissLabel: "Dismiss message",
                                onDismiss: () => setVersionMessage([]),
                                id: "message_1"
                              }
          ]);
      
        }
        
   }
   
   
   useEffect(() => {
        gatherVersion();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
  
  return (
      
    <div>
      <CustomHeader/>
      <AppLayout
            toolsHide
            navigationHide
            contentType="default"
            content={
              <ContentLayout 
                          header = {
                                   <>
                                      <Flashbar items={versionMessage} />
                                      <br/>
                                      <Header variant="h1">
                                              Welcome to {configuration["apps-settings"]["application-title"]}
                                      </Header>                                      
                                      <br/>
                                      <Box fontSize="heading-s">
                                          {configuration["apps-settings"]["application-title"]} a revolutionary serverless application designed to streamline and enhance your AWS metadata management. 
                                          <br/>
                                          <br/>
                                          This powerful tool automates the tagging process across multiple accounts and regions, providing unprecedented control and visibility over your cloud infrastructure. 
                                          With its advanced filtering capabilities and comprehensive metadata management, 
                                          <br/>
                                          <br/>                                              
                                          {configuration["apps-settings"]["application-title"]} empowers organizations to optimize their AWS resources, improve cost allocation, and enhance security compliance effortlessly.
                                    
                                      </Box>
                                      <br/>
                                  </>

                                }
                                
                    >
                  
                    <div>
                    <ColumnLayout columns={2} >
                      
                            <div>
                                <Container
                                      header = {
                                        <Header variant="h2">
                                          Key features
                                        </Header>
                                        
                                      }
                                  >

                                <ul>
                                  <li>Cross-account and cross-region automated tagging.</li>
                                  <br/>
                                  <li>Custom tag filtering for precise resource management.</li>
                                  <br/>
                                  <li>Comprehensive metadata search functionality.</li>
                                  <br/>
                                  <li>Fully serverless architecture for scalability and cost-efficiency.</li>
                                  <br/>
                                </ul>                                                                       
                              </Container>
                              
                          </div>
                    
                          <div>
                                    <Container
                                          header = {
                                            <Header variant="h2">
                                              Getting Started
                                            </Header>
                                            
                                          }
                                      >
                                            <div>
                                              <Box variant="p">
                                                  Start unlocking the true potential of your metadata management.
                                              </Box>
                                              <br/>
                                              <Button variant="primary" href="/dashboard/" >Get Started</Button>
                                              <br/>
                                              <br/>
                                            </div>
                                  </Container>
                                  
                          </div>
                              
                          
                          </ColumnLayout>
                          <br/>
                          <Container
                                      header = {
                                        <Header variant="h2">
                                          Use cases
                                        </Header>
                                        
                                      }
                                  >
                                         <ColumnLayout columns={1} variant="text-grid">
                                              <div>
                                                <Header variant="h3">
                                                Cost Allocation
                                                </Header>
                                                <Box variant="p">
                                                A large enterprise uses {configuration["apps-settings"]["application-title"]} to automatically tag resources across multiple departments, enabling accurate cost attribution and budgeting.                                                
                                                </Box>
                                              </div>
                                              
                                              <div>
                                                <Header variant="h3">
                                                Security Compliance
                                                </Header>
                                                <Box variant="p">
                                                A financial services company leverages the application to ensure all resources are properly tagged for regulatory compliance, using custom filters to identify and rectify any non-compliant resources.
                                                </Box>
                                              </div>
                                              <div>
                                                <Header variant="h3">
                                                Resource Optimization
                                                </Header>
                                                <Box variant="p">
                                                A startup uses the metadata search feature to quickly locate underutilized resources across their AWS infrastructure, allowing them to optimize their cloud spend and improve efficiency.
                                                </Box>
                                              </div>
                                              

                                        </ColumnLayout>
                              </Container>

                              <br/>
                              <Container
                                      header = {
                                        <Header variant="h2">
                                          Architecture
                                        </Header>
                                        
                                      }
                                  >
                                    <br/>
                                    <SegmentedControl
                                        selectedId={selectedId}
                                        onChange={({ detail }) =>
                                          setSelectedId(detail.selectedId)
                                        }                                        
                                        options={[
                                          { text: "Public", id: "public" },
                                          { text: "Private", id: "private" }                                          
                                        ]}
                                    />
                                    <br/>                                    
                                    <img style={{ "max-width" :"100%" }} src={ selectedId == "public" ? architecturePublic : architecturePrivate} alt="Architecture" />
                                    

                              </Container>
                              
                              
                          </div>
                      </ContentLayout>
            }
          />
    </div>
    
  );
}

export default Home;
