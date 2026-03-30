import { render } from "react-dom";
import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";

//-- Libraries
import '@cloudscape-design/global-styles/index.css';
import { Amplify } from "aws-amplify";
import { AmplifyProvider, Authenticator } from "@aws-amplify/ui-react";
import { StrictMode } from "react";
import Axios from "axios";

//-- Pages
import Authentication from "./pages/Authentication";
import Home from "./pages/Home";
import Logout from "./pages/Logout";
import SmTagger01 from "./pages/Sm-tagger-01";
import SmTagger02 from "./pages/Sm-tagger-02";
import SmDashboard01 from "./pages/Sm-dashboard-01";
import SmProfiles01 from "./pages/Sm-profiles-01";
import SmMetadataBase01 from "./pages/Sm-metadata-base-01";
import SmMetadataSearch01 from "./pages/Sm-metadata-search-01";
import SmModules01 from "./pages/Sm-modules-01";
import SmModules02 from "./pages/Sm-modules-02";
import SmCompliance01 from "./pages/Sm-compliance-01";

//-- Components
import ProtectedApp from "./components/ProtectedApp";
import { AmplifyTheme } from './components/AmplifyTheme';
import { applyMode,  Mode } from '@cloudscape-design/global-styles';

if (localStorage.getItem("themeMode") === null ){
    localStorage.setItem("themeMode", "light");
}

if (localStorage.getItem("themeMode") == "dark")
    applyMode(Mode.Dark);
else
    applyMode(Mode.Light);
  


Axios.get(`/aws-exports.json`,).then((data)=>{

    var configData = data.data;
    Amplify.configure({
                    Auth: {
                      region: configData.aws_region,
                      userPoolId: configData.aws_cognito_user_pool_id,
                      userPoolWebClientId: configData.aws_cognito_user_pool_web_client_id,
                    },
    });
                  
    const rootElement = document.getElementById("root");
    render(
      <StrictMode>
        <AmplifyProvider theme={AmplifyTheme}>
          <Authenticator.Provider>
              <BrowserRouter>
                <Routes>
                    <Route path="/" element={<ProtectedApp><Home /> </ProtectedApp>} />
                    <Route path="/tagger/" element={<ProtectedApp><SmTagger01 /> </ProtectedApp>} />
                    <Route path="/dashboard/" element={<ProtectedApp><SmDashboard01 /> </ProtectedApp>} />
                    <Route path="/profiles/" element={<ProtectedApp><SmProfiles01 /> </ProtectedApp>} />
                    <Route path="/modules/" element={<ProtectedApp><SmModules01 /> </ProtectedApp>} />
                    <Route path="/modules/validation/" element={<ProtectedApp><SmModules02 /> </ProtectedApp>} />
                    <Route path="/metadata/bases/" element={<ProtectedApp><SmMetadataBase01 /> </ProtectedApp>} />
                    <Route path="/metadata/search/" element={<ProtectedApp><SmMetadataSearch01 /> </ProtectedApp>} />                    
                    <Route path="/compliance/" element={<ProtectedApp><SmCompliance01 /> </ProtectedApp>} />           
                    <Route path="/remediate/" element={<ProtectedApp><SmTagger02 /> </ProtectedApp>} />         
                    <Route path="/authentication" element={<Authentication />} />
                    <Route path="/logout" element={<ProtectedApp><Logout /> </ProtectedApp>} />
                </Routes>
              </BrowserRouter>
          </Authenticator.Provider>
        </AmplifyProvider>
      </StrictMode>,
      rootElement
    );

})
.catch((err) => {
    console.log('API Call error : ./aws-exports.json' );
    console.log(err)
});
              
              

