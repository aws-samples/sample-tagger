import { render } from "react-dom";
import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";

//-- Libraries
import '@cloudscape-design/global-styles/index.css';
import './styles/css/default.css';
import { StrictMode } from "react";

//-- Pages
import Home from "./pages/Home";
import SmTagger01 from "./pages/Sm-tagger-01";
import SmTagger02 from "./pages/Sm-tagger-02";
import SmTagger03 from "./pages/Sm-tagger-03";
import SmDashboard01 from "./pages/Sm-dashboard-01";
import SmProfiles01 from "./pages/Sm-profiles-01";
import SmMetadataBase01 from "./pages/Sm-metadata-base-01";
import SmMetadataBase02 from "./pages/Sm-metadata-base-02";
import SmModules01 from "./pages/Sm-modules-01";
import SmModules02 from "./pages/Sm-modules-02";
import SmCompliance01 from "./pages/Sm-compliance-01";
import SmCompliance02 from "./pages/Sm-compliance-02";
import SmTagExplorer01 from "./pages/Sm-TagExplorer-01";

//-- Components
import ErrorBoundary from "./components/ErrorBoundary";
import { applyMode,  Mode } from '@cloudscape-design/global-styles';

if (localStorage.getItem("themeMode") === null ){
    localStorage.setItem("themeMode", "light");
}

if (localStorage.getItem("themeMode") == "dark")
    applyMode(Mode.Dark);
else
    applyMode(Mode.Light);

// Comprehensive ResizeObserver error suppression
// These errors are benign and come from CloudScape components measuring DOM elements

// Method 1: Suppress at window.error level
window.addEventListener('error', (e) => {
  if (e.message && (
      e.message.includes('ResizeObserver') ||
      e.message.includes('ResizeObserver loop') ||
      e.message === 'ResizeObserver loop completed with undelivered notifications.' ||
      e.message === 'ResizeObserver loop limit exceeded'
  )) {
    e.stopImmediatePropagation();
    e.preventDefault();
    return false;
  }
});

// Method 2: Suppress at unhandledrejection level
window.addEventListener('unhandledrejection', (e) => {
  if (e.reason && e.reason.message && e.reason.message.includes('ResizeObserver')) {
    e.preventDefault();
    return false;
  }
});

// Method 3: Override console.error to filter ResizeObserver errors
const originalConsoleError = console.error;
console.error = (...args) => {
  const errorMessage = args[0]?.toString() || '';
  if (errorMessage.includes('ResizeObserver')) {
    // Silently ignore ResizeObserver errors
    return;
  }
  originalConsoleError.apply(console, args);
};

const rootElement = document.getElementById("root");
render(
  <StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/tagger/" element={<SmTagger01 />} />
            <Route path="/tagger/process/" element={<SmTagger03 />} />
            <Route path="/dashboard/" element={<SmDashboard01 />} />
            <Route path="/profiles/" element={<SmProfiles01 />} />
            <Route path="/modules/" element={<SmModules01 />} />
            <Route path="/modules/validation/" element={<SmModules02 />} />
            <Route path="/metadata/bases/" element={<SmMetadataBase01 />} />
            <Route path="/metadata/process/" element={<SmMetadataBase02 />} />            
            <Route path="/metadata/explorer/" element={<SmTagExplorer01 />} />
            <Route path="/compliance/" element={<SmCompliance01 />} />
            <Route path="/compliance/process/" element={<SmCompliance02 />} />           
            <Route path="/remediate/" element={<SmTagger02 />} />         
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  </StrictMode>,
  rootElement
);
              
              

