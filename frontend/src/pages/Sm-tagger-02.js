import {useState,useEffect,useRef, useCallback} from 'react'
import { useNavigate } from "react-router-dom";
import { useSearchParams } from 'react-router-dom';

//--## CloudScape components
import {
        AppLayout,
        SideNavigation,
        ContentLayout,
        Header,
        SpaceBetween,
        Button,
        Modal,
        Box,
        Flashbar,
        Select,
        FormField,
        Container,
        StatusIndicator,
        ButtonDropdown,
        Input,
        TagEditor,
        Alert,
        Checkbox,
        Wizard,
        Textarea,
        TokenGroup,
        Icon,
        KeyValuePairs,
        Badge,
        Link,
        Toggle
} from '@cloudscape-design/components';

import LoadingBar from "@cloudscape-design/chat-components/loading-bar";


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs, tagEditorI18n } from './Configs';
import { createLabelFunction } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CodeEditor01  from '../components/CodeEditor01';
import CustomTable01 from "../components/Table01";
import CustomTable02 from "../components/Table02";
import CustomTable03 from "../components/Table03";
import TokenGroupReadOnly01 from '../components/TokenGroupReadOnly01';
import ProcessLogsComponent from '../components/ProcessLogs-01';
import TagEditorComponent from '../components/TagEditor-01';



//--## Main function
function Application() {

    //-- Navigate object
    let navigate = useNavigate();

    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
    const [navigationOpen, setNavigationOpen] = useState(false);

    //-- Customize mode
    const [customizeMode, setCustomizeMode] = useState(false);

    //-- Table columns Resources
    const columnsTableResources = [
        {id: 'action',header: 'Action',cell: item => (
          <StatusIndicator type={item['action'] == "1" ? "success" : item['action'] == "2" ? "error" : "pending"}>
            {item['action'] == "1" ? "Included" : item['action'] == "2" ? "Excluded" : "Unknown"}
          </StatusIndicator>
        ),ariaLabel: createLabelFunction('action'),sortingField: 'action',},
        {id: 'account',header: 'Account',cell: item => item['account'],ariaLabel: createLabelFunction('account'),sortingField: 'account',},
        //{id: 'account',header: 'Account',cell: item => "1234567890",ariaLabel: createLabelFunction('account'),sortingField: 'account',},
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
    var fetchSize = useRef(500); // Pre-fetch size for Table03

    //-- Table key for forcing refresh
    const [tableKey, setTableKey] = useState(0);

    //-- Selected resources for multi-selection
    const [selectedResources, setSelectedResources] = useState([]);

    //-- Process logs
    const [processLogs, setProcessLogs] = useState("");
    const [lastLogLine, setLastLogLine] = useState("");

    //-- Ruleset
    var txtRuleset = useRef("");
    const [selectedRuleSet,setSelectedRuleSet] = useState({});
    const [datasetRuleSet,setDatasetRuleSet] = useState([]);

    //-- Get Parameters
    const [params]=useSearchParams();
    var currentScanId = useRef(params.get("scan_id") || params.get("mtid")); // Primary: scan_id, fallback: mtid for backward compatibility


    //-- Tasks
    const timeoutRef = useRef(null);

    //-- Scan process
    const [searchStatus, setSearchStatus] = useState('idle');
    const [searchSummary, setSearchSummary] = useState({ action : 0 });
    const [taggingStatus, setTaggingStatus] = useState('idle');

    //-- Selected options filters
    const [selectedAccounts,setSelectedAccounts] = useState([]);
    const [selectedRegions,setSelectedRegions] = useState([]);
    const [selectedServices,setSelectedServices] = useState([]);
    const [selectedTags,setSelectedTags] = useState([]);
    const accountList = useRef([]);
    const regionList = useRef([]);
    const serviceList = useRef([]);
    const tagList = useRef([]);

    const [inputAccounts, setInputAccounts] = useState("");
    const [inputRegions, setInputRegions] = useState("");
    const [inputServices, setInputServices] = useState("");

    const [selectedAction,setSelectedAction] = useState({ label: "Add tags", value: 1 });
    const actionTags = useRef(1);

    //-- Filter
    const [selectedFilter,setSelectedFilter] = useState("");
    const filterList = useRef("");

    //-- Start tagging process
    const [checkedKnowledge, setCheckedKnowledge] = useState(false);
    var taggingState = useRef("Not-Started");

    //-- Filter Action
    const [selectedFilterAction, setSelectedFilterAction] = useState({ label : 'Resources included', value : "1" });
    const filterAction = useRef("1");

    //-- Update actions
    const resourceId = useRef({});
    const actionType = useRef("0");

    //-- Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);

    //-- Table columns Tags
    const columnsTableTags = [
        {id: 'key',header: 'Key',cell: item => item.key,ariaLabel: createLabelFunction('key'),sortingField: 'key', width : "250px"},
        {id: 'value',header: 'Value',cell: item => item.value,ariaLabel: createLabelFunction('value'),sortingField: 'value',},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags,setItemsTableTags] = useState([]);

    //-- Modal Metadata
    const [visibleShowMetadata, setVisibleShowMetadata] = useState(false);
    const [metadata,setMetadata] = useState("");

    //-- Wizard variables
    const [activeStepIndex,setActiveStepIndex] = useState(0);
    var currentStep = useRef(0);

    //-- Tag errors
    const [datasetTagErrors, setDatasetTagErrors] = useState([]);
    const [visibleTaggingErrors, setVisibleTaggingErrors] = useState(false);




    //--## Show tags for specific resource
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




    //--## Create API object
    function createApiObject(object){
            const xhr = new XMLHttpRequest();
            xhr.open(object.method,`${configuration["apps-settings"]["api-url"]}`,object.async);
            xhr.setRequestHeader("Content-Type","application/json");
            return xhr;
    }




    //--## Gather Metadata Information
    async function gatherMetadataInformation(){
      try {

            var parameters = {
                            processId : 'metadata::api-007-get-dataset-metadata-information',
                            scanId : currentScanId.current
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          var parameters = JSON.parse(response['processes']['parameters']);
                          refreshParameters(parameters);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 15-get-dataset-metadata-information');
      }
    };




    //--## Refresh Discovery parameters
    function refreshParameters(parameters){

            //-- Create tag list
            var tags = [];
            parameters['tags'].forEach( element => {
              tags.push({ key: element['key'], value: element['value'] });
            });
            setSelectedTags(tags);
            tagList.current = tags;
    }




    //--## Show messages
    function showMessage(object){
          setApplicationMessage([
                {
                  type: object.type,
                  content: object.content,
                  dismissible: true,
                  dismissLabel: "Dismiss message",
                  onDismiss: () => setApplicationMessage([]),
                  id: "message_1"
                }
          ]);
    }




    //--## Get task information
    async function getScanResults(){
          try {

                var parameters = {
                                processId : 'metadata::api-001-get-metadata-results',
                                scanId : currentScanId.current,
                                ruleset : txtRuleset.current,
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
                              setDatasetResources(response['resources']);
                          }
                };
                api.send(JSON.stringify({ parameters : parameters }));

          }
          catch(err){
                console.log(err);
                console.log('Timeout API error - PID: 03-get-task-information');
          }
    };




    //--## Get task information (for Table03 pre-fetching)
    async function fetchScanResults({ page, limit }){
          return new Promise((resolve, reject) => {
                try {
                      var parameters = {
                                      processId : 'metadata::api-001-get-metadata-results',
                                      scanId : currentScanId.current,
                                      ruleset : txtRuleset.current,
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
                      console.log('Timeout API error - PID: 03-get-task-information');
                      reject(err);
                }
          });
    };



    //--## Get scan logs
    async function getScanLogs(lines = 500){
      try {

            var parameters = {
                            processId : 'tagger::api-106-get-scan-logs',
                            scanId : currentScanId.current,
                            lines : lines
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          if (response['exists']) {
                            const content = response['content'];
                            setProcessLogs(content);
                            // Extract first line for loading bar (logs are in reverse chronological order)
                            const logLines = content.trim().split('\n');
                            if (logLines.length > 0) {
                              // Get first line since logs are newest-first
                              setLastLogLine(logLines[0]);
                            }
                          } else {
                            setProcessLogs('No logs available for this process.');
                            setLastLogLine('');
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




    //--## Get tagging errors
    async function getTaggingErrors(){
      try {

            var parameters = {
                            processId : 'tagger::api-105-get-tagging-errors',
                            scanId : currentScanId.current,
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          setDatasetTagErrors(response['resources']);
                          setVisibleTaggingErrors(true);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 23-get-tagging-errors');
      }
    };



    //--## Update resource action (supports batch updates)
    async function updateResourceAction(){
      try {

            // Check if we have selected resources (batch mode) or single resource
            const isBatchMode = selectedResources.length > 0;

            var parameters = {
                            processId : 'tagger::api-101-update-resource-action',
                            action : actionType.current
            };

            if (isBatchMode) {
              // Batch mode: send array of resources
              parameters.resources = selectedResources.map(item => ({
                scan_id: item.scan_id,
                seq: item.seq
              }));
            } else {
              // Single resource mode (legacy)
              parameters.scanId = resourceId.current['scan_id'];
              parameters.seq = resourceId.current['seq'];
            }

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          // Clear selection after successful update
                          setSelectedResources([]);
                          // Refresh table
                          setTableKey(prev => prev + 1);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 02-create-metadata-search');
      }
    };




    //--## Get tagging status
    const getTaggingProcessStatus = useCallback(async () => {

      try {

          var parameters = {
                          processId : 'tagger::api-103-get-tagging-process-status',
                          scanId : currentScanId.current
          };

          const api = createApiObject({ method : 'POST', async : true });
          api.onload = function() {
                    if (api.status === 200) {
                        var response = JSON.parse(api.responseText)?.['response'];

                        //-- Fetch logs while in progress
                        if (response['status'] === 'in-progress') {
                          getScanLogs();
                        }

                        //-- Use metrics from API response directly
                        var metrics = response['metrics'] || { total: 0, success: 0, failed: 0 };

                        if (response['status'] === 'completed') {
                            setTaggingStatus('completed');
                            getScanLogs(); // Final log fetch
                            if (!response['has_errors']) {
                              showMessage({ type : "success", content : `Tagging process ${currentScanId.current} has been completed. Success (${metrics.success || 0}), Errors (${metrics.failed || 0}).` });
                            }
                            else{
                              showMessage({
                                            type : "error",
                                            content : (
                                              <>
                                                  Tagging process {currentScanId.current} has been completed. Success ({metrics.success || 0}), Errors ({metrics.failed || 0}).
                                                  <Link
                                                        color="inverted"
                                                        onFollow={() => {
                                                                getTaggingErrors();
                                                        }}
                                                    >
                                                    View errors.
                                                  </Link>
                                              </>
                                            )
                              });
                            }

                        } else if (response['status'] === 'failed') {
                            setTaggingStatus('failed');
                            getScanLogs();
                        } else {
                          timeoutRef.current = setTimeout(getTaggingProcessStatus, 3000);
                        }

                    }
          };
          api.send(JSON.stringify({ parameters : parameters }));

      } catch (err) {
        console.log('Timeout API error - PID: 03-get-metadata-search-status');
        console.error(err);
      }
    }, []);



    /*
    //--## Get tagging status
    const getTaggingProcessStatus = useCallback(async () => {

      try {

          var parameters = {
                          processId : 'tagger::api-103-get-tagging-process-status',
                          scanId : currentScanId.current
          };

          const api = createApiObject({ method : 'POST', async : true });
          api.onload = function() {
                    if (api.status === 200) {
                        var response = JSON.parse(api.responseText)?.['response'];
                        var message = JSON.parse(response['message']);
                        if (response['status'] === 'completed') {
                            setTaggingStatus('completed');
                            showMessage({ type : "success", content : `Tagging process ${currentScanId.current} has been completed. Success (${message['success'] || 0 }), Errors (${message['error'] || 0 }).` });
                        } else if (response['status'] === 'failed') {
                            setTaggingStatus('failed');
                        } else {
                          timeoutRef.current = setTimeout(getTaggingProcessStatus, 5000);
                        }

                    }
          };
          api.send(JSON.stringify({ parameters : parameters }));

      } catch (err) {
        console.log('Timeout API error - PID: 03-get-metadata-search-status');
        console.error(err);
      }
    }, []);
    */



    //--## Start tagging process
    const handleStartTaggingProcess = useCallback(() => {

      try {
            // Clear old logs from discovery phase
            setProcessLogs("");
            setLastLogLine("Initializing tagging process...");

            setTaggingStatus("in-progress");
            var parameters = {
                            processId : 'tagger::api-102-create-tagging-process',
                            scanId : currentScanId.current,
                            tags : tagList.current,
                            action : actionTags.current
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          getTaggingProcessStatus();
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 05-create-tagging-process');
      }

    }, [getTaggingProcessStatus]);




    //--## Convert list of tags to tokens
    const convertTagsToTokens = (tags) => {
      if (tags.length > 0) {
            return tags.map((tag, index) => ({
              label: `${tag.key} = ${tag.value}`,
              dismissLabel: `Remove ${tag.key}`,
              value: String(index)
            }));
      }
    };




    //--## Goto to compliance page
    function handleGotoDashboard(){
      navigate('/compliance');
    }



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherMetadataInformation();
    }, []);



    //--## Rendering
    return (
    <div style={{"background-color": "#f2f3f3"}}>
        <CustomHeader/>
        <AppLayout
            breadCrumbs={breadCrumbs}
            navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/workloads/"} />}
            navigationOpen={navigationOpen}
            onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
            disableContentPaddings={true}
            contentType="dashboard"
            toolsHide={true}
            content={
                      <ContentLayout
                          defaultPadding
                          header={
                              <Header
                                variant="h1"
                                description="Manage tag operations and apply changes to selected AWS resources from your discovery process."
                              >
                                Remediation process ({currentScanId.current})
                              </Header>
                          }
                      >
                      <Container>
                          {/* ----### Wizard */}
                          <Wizard
                              i18nStrings={{
                                            stepNumberLabel: stepNumber =>
                                              `Step ${stepNumber}`,
                                            collapsedStepsLabel: (stepNumber, stepsCount) =>
                                              `Step ${stepNumber} of ${stepsCount}`,
                                            skipToButtonLabel: (step, stepNumber) =>
                                              `Skip to ${step.title}`,
                                            navigationAriaLabel: "Steps",
                                            cancelButton: "Cancel",
                                            previousButton: "Previous",
                                            nextButton: "Next",
                                            submitButton: "Close",
                                            optional: "optional"
                              }}
                              onNavigate={({ detail }) => {

                                //-- Block forward navigation if viewing excluded resources on step 1
                                if (activeStepIndex === 1 && detail.requestedStepIndex > activeStepIndex && selectedFilterAction?.value === "2") {
                                  showMessage({ type: "warning", content: "Switch to 'Resources included' before proceeding to the next step." });
                                  return;
                                }

                                //-- Block forward navigation if no included resources on step 1
                                if (activeStepIndex === 1 && detail.requestedStepIndex > activeStepIndex && selectedFilterAction?.value === "1" && totalRecords.current === 0) {
                                  showMessage({ type: "error", content: "No resources included. Move excluded resources back to included before proceeding." });
                                  return;
                                }

                                setActiveStepIndex(detail.requestedStepIndex);
                                currentStep.current = detail.requestedStepIndex;
                                if (detail.requestedStepIndex == 1)
                                {
                                  pageId.current = 0;
                                  getScanResults();
                                }
                                setApplicationMessage([]);

                              }}
                              onSubmit={
                                handleGotoDashboard
                              }
                              onCancel={
                                handleGotoDashboard
                              }
                              activeStepIndex={activeStepIndex}
                              isLoadingNextStep={ searchStatus== "in-progress" }
                              steps={[
                                {
                                  title: "Manage tags",
                                  description: "Select action to be performed and define list of tags for resources selected.",
                                  content: (
                                            <Container>
                                              <table style={{"width":"100%"}}>
                                                <tr>
                                                  <td valign="bottom" style={{"width":"25%", "padding-right": "2em"}}>
                                                    <FormField label={"Action"}>
                                                        <Select
                                                            selectedOption={selectedAction}
                                                            onChange={({ detail }) => {
                                                                setSelectedAction(detail.selectedOption);
                                                                actionTags.current = detail.selectedOption['value'];
                                                            }}
                                                            options={[
                                                              { label: "Add tags", value: 1, iconName: "status-positive" },
                                                            ]}
                                                        />
                                                    </FormField>
                                                  </td>
                                                  <td valign="bottom" style={{"width":"15%"}}>
                                                    <FormField label={"Customize"}>
                                                        <Toggle
                                                            onChange={({ detail }) => setCustomizeMode(detail.checked)}
                                                            checked={customizeMode}
                                                        >
                                                            {customizeMode ? "On" : "Off"}
                                                        </Toggle>
                                                    </FormField>
                                                  </td>
                                                  <td style={{"width":"60%"}}></td>
                                                </tr>
                                              </table>
                                              <br/>
                                              <FormField label={"Tags"}>
                                                  <TagEditorComponent
                                                      value={selectedTags}
                                                      readOnly={!customizeMode}
                                                      onChange={({ detail }) => {
                                                          setSelectedTags(detail.tags);
                                                          tagList.current = detail.tags;
                                                      }}
                                                  />
                                              </FormField>
                                          </Container>
                                  )
                                },
                                {
                                  title: "Review resource selection",
                                  description: "Review resources selected, define to which ones apply tag actions, this definition will be used by tagging process.",
                                  content: (
                                    <div>
                                            <Flashbar items={applicationMessage} />
                                            <br/>
                                            {/* ----### Resources Table */}
                                            <CustomTable03
                                                key={tableKey}
                                                columnsTable={columnsTableResources}
                                                visibleContent={visibleContentResources}
                                                title={"Resources"}
                                                description={"Select resources to move between excluded and included"}
                                                fetchSize={fetchSize.current}
                                                displayPageSize={pageSize.current}
                                                totalRecords={totalRecords.current}
                                                selectionType="multi"
                                                onFetchData={fetchScanResults}
                                                onSelectionChange={( items ) => {
                                                    setSelectedResources(items);
                                                }}
                                                loading={searchStatus=="in-progress"}
                                                tableActions={
                                                            <SpaceBetween
                                                              direction="horizontal"
                                                              size="xs"
                                                            >
                                                              <Button iconName="refresh" onClick={() => {
                                                                      setTableKey(prev => prev + 1);
                                                              }}></Button>
                                                              <Select
                                                                  selectedOption={selectedFilterAction}
                                                                  onChange={({ detail }) => {
                                                                      setSelectedFilterAction(detail.selectedOption);
                                                                      filterAction.current = detail.selectedOption['value'];
                                                                      // Clear selections when changing filter
                                                                      setSelectedResources([]);
                                                                      setTableKey(prev => prev + 1);
                                                                    }
                                                                  }
                                                                  options={[
                                                                    { label: "Resources included", value: "1" },
                                                                    { label: "Resources excluded", value: "2" }
                                                                  ]}
                                                              />
                                                              <Button
                                                                  variant="primary"
                                                                  onClick={() => {
                                                                    // Toggle action based on current filter
                                                                    if (selectedFilterAction.value === "1") {
                                                                      actionType.current = "2";
                                                                    } else {
                                                                      actionType.current = "1";
                                                                    }
                                                                    updateResourceAction();
                                                                  }}
                                                                  disabled={selectedResources.length === 0}
                                                              >
                                                                {selectedFilterAction.value === "1"
                                                                  ? `Move ${selectedResources.length > 0 ? selectedResources.length : ''} to excluded`.trim()
                                                                  : `Move ${selectedResources.length > 0 ? selectedResources.length : ''} to included`.trim()}
                                                              </Button>
                                                            </SpaceBetween>
                                                }
                                              />

                                      </div>
                                  )
                                },
                                {
                                  title: "Launch tagging process",
                                  description: "Start tagging process for resources according actions selected.",
                                  content: (
                                              <Container>
                                                  <Flashbar items={applicationMessage} />
                                                  <br/>
                                                  {/* ----### Tagging Summary */}
                                                  <KeyValuePairs
                                                      columns={4}
                                                      items={[
                                                        {
                                                          label: "Process identifier",
                                                          value: currentScanId.current,
                                                        },
                                                        {
                                                          label: "Action",
                                                          value: (
                                                            <StatusIndicator
                                                              type={ ( selectedAction['value'] == 1 ? "success" : "error")}
                                                            >
                                                                {selectedAction['label']}
                                                            </StatusIndicator>
                                                          )
                                                        },
                                                        {
                                                          label: "Resources",
                                                          value: totalRecords.current,
                                                        },
                                                        {
                                                          label: "Tags",
                                                          value: selectedTags.length,
                                                        },
                                                      ]}
                                                    />
                                                  <br/>

                                                  {/* ----### Loading Bar for Tagging */}
                                                  {taggingStatus === 'in-progress' && (
                                                    <>
                                                      <Container
                                                        header={
                                                          <Header
                                                            variant="h3"
                                                            description="Applying tag operations to AWS resources"
                                                          >
                                                            Tagging in progress
                                                          </Header>
                                                        }
                                                      >
                                                        <SpaceBetween size="s">
                                                          <LoadingBar
                                                            variant="gen-ai"
                                                          />
                                                          <Box color="text-body-secondary" fontSize="body-s">
                                                            <div>This may take several minutes depending on the number of resources being processed.</div>
                                                            <div style={{ marginTop: '8px' }}>You can monitor the progress in the process logs below.</div>
                                                            {lastLogLine && (
                                                              <div style={{ marginTop: '8px', fontStyle: 'italic' }}>
                                                                {lastLogLine}
                                                              </div>
                                                            )}
                                                          </Box>
                                                        </SpaceBetween>
                                                      </Container>
                                                      <br/>
                                                    </>
                                                  )}

                                                  {/* ----### Acknowledgment Alert */}
                                                  <Alert
                                                          statusIconAriaLabel="Info"
                                                          header="By proceeding with this tagging process for AWS resources, you acknowledge and agree to the following:"
                                                        >
                                                          <br/>
                                                          1.- You understand that this process will modify resource tags across multiple AWS resources in your account(s).
                                                          <br/>
                                                          <br/>
                                                          2.- You have reviewed and verified the tagging specifications and confirm they align with your organization's tagging strategy and compliance requirements.
                                                          <br/>
                                                          <br/>
                                                          3.-You have taken necessary backups and/or documented the current tag state of affected resources before proceeding.
                                                          <br/>
                                                          <br/>
                                                          4.- You confirm you have the necessary permissions and authority to perform these changes.
                                                          <br/>
                                                          <br/>
                                                          5.-You accept full responsibility for any unintended consequences that may arise from this mass tagging operation, effects on automated processes that rely on tags, potential disruption to existing tag-based permissions or policies.
                                                          <br/>
                                                          <br/>
                                                          By proceeding, you indicate that you have read, understood, and agreed to the above statements.
                                                          <br/>
                                                          <br/>
                                                          <Checkbox
                                                              onChange={({ detail }) =>
                                                                setCheckedKnowledge(detail.checked)
                                                              }
                                                              checked={checkedKnowledge}
                                                              disabled={( taggingState.current == "Not-Started" ? false : true )}
                                                            >
                                                              I acknowledge.
                                                          </Checkbox>

                                                  </Alert>
                                                  <br/>

                                                  { ( taggingState.current == "Not-Started"  ) && (
                                                    <>
                                                      <Box float="right">
                                                        <div className="custom-orange-button">
                                                          <Button
                                                            variant="primary"
                                                            onClick={handleStartTaggingProcess}
                                                            disabled={ ( ( taggingStatus=="in-progress" || checkedKnowledge == false || ( filterAction.current == "2" && totalRecords.current > 0)  )  ? true : false )}
                                                            loading={(taggingStatus=="in-progress" ? true : false )}
                                                          >
                                                            { ( selectedAction['value'] == 1 ? "Proceed to add the tags" : "Proceed to remove the tags")}
                                                          </Button>
                                                        </div>
                                                      </Box>
                                                      <br/>
                                                    </>
                                                  )}

                                                  {/* ----### Tagging Process Logs */}
                                                  {taggingStatus !== 'idle' && (
                                                    <>
                                                      <ProcessLogsComponent
                                                        logs={processLogs}
                                                        theme="dark"
                                                        headerText="Process logs"
                                                        defaultExpanded={false}
                                                        variant="footer"
                                                      />
                                                      <br/>
                                                    </>
                                                  )}

                                              </Container>
                                  )
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


          {/* ----### Metadata Modal */}
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

          {/* ----### Tagging Errors Modal */}
          <Modal
            onDismiss={() => setVisibleTaggingErrors(false)}
            visible={visibleTaggingErrors}
            footer={
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="primary"
                              onClick={() => {
                                setVisibleTaggingErrors(false);
                                    }}
                      >
                          Close
                      </Button>
                </SpaceBetween>
              </Box>
            }
            header="Tagging errors"
            size="max"
          >
              <CodeEditor01
                format={"json"}
                value={JSON.stringify(datasetTagErrors,null,4)}
                readOnly={true}
              />
          </Modal>

    </div>
  );
}

export default Application;
