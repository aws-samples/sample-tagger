import {useState,useEffect,useRef, useCallback} from 'react'
import { useNavigate } from "react-router-dom";

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
        Icon,
        KeyValuePairs,
        Badge,
        Link,
        ExpandableSection,
        Toggle
} from '@cloudscape-design/components';

import LoadingBar from "@cloudscape-design/chat-components/loading-bar";


//--## Functions
import { configuration, SideMainLayoutHeader,SideMainLayoutMenu, breadCrumbs } from './Configs';
import { createLabelFunction } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CodeEditor01  from '../components/CodeEditor01';
import CustomTable01 from "../components/Table01";
import CustomTable03 from "../components/Table03";
import ProcessLogs01 from "../components/ProcessLogs-01";
import WhereClauseBuilder01 from '../components/WhereClauseBuilder01';
import AccountEditorComponent from '../components/AccountEditor-01';
import RegionEditorComponent from '../components/RegionEditor-01';
import ServiceEditorComponent from '../components/ServiceEditor-01';
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
          <StatusIndicator type={item['action'] == "1" ? "success" : (item['action'] == "2" ? "error" : "pending")}>
            {item['action'] == "1" ? "Included" : (item['action'] == "2" ? "Excluded" : "Unknown")}
          </StatusIndicator>
        ), ariaLabel: createLabelFunction('action'), sortingField: 'action'},
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

    //-- Ruleset
    var txtRuleset = useRef("");
    const [selectedRuleSet,setSelectedRuleSet] = useState({});
    const [datasetRuleSet,setDatasetRuleSet] = useState([]);

    var currentScanId = useRef("");

    //-- Paging
    const pageId = useRef(0);
    var totalPages = useRef(1);
    var totalRecords = useRef(0);
    var pageSize = useRef(20);
    var fetchSize = useRef(100); // Pre-fetch size for Table03



    //-- Tasks
    const timeoutRef = useRef(null);

    //-- Scan process
    const [searchStatus, setSearchStatus] = useState('idle');
    const [searchSummary, setSearchSummary] = useState({ action : 0 });
    const [taggingStatus, setTaggingStatus] = useState('idle');
    const searchStartTime = useRef(null);
    const taggingStartTime = useRef(null);
    const MAX_POLL_TIME = 600000; // 10 minutes timeout

    //-- Selected options filters
    const [selectedAccounts,setSelectedAccounts] = useState([]);
    const [selectedRegions,setSelectedRegions] = useState([]);
    const [selectedServices,setSelectedServices] = useState([]);
    const [selectedTags,setSelectedTags] = useState([]);
    const accountList = useRef([]);
    const regionList = useRef([]);
    const serviceList = useRef([]);
    const tagList = useRef([]);

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
    const [tableKey, setTableKey] = useState(0); // Key to force table re-mount

    //-- Update actions
    const resourceId = useRef({});
    const selectedResources = useRef([]);
    const [selectedCount, setSelectedCount] = useState(0);
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

    //-- Logs
    const [searchLogs, setSearchLogs] = useState("");
    const [taggingLogs, setTaggingLogs] = useState("");
    const searchLogInterval = useRef(null);
    const taggingLogInterval = useRef(null);




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




    //--## Handle WhereClause change
    const handleWhereClauseChange = useCallback((newValue) => {
        console.log("changed");
    }, []);




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

                                txtRuleset.current = items[0]['parameters'];
                                refreshParameters(JSON.parse(items[0]['parameters']));
                                setSelectedRuleSet(items[0]);
                          }

                          setDatasetRuleSet(items);

                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 12-get-profiles');
      }
    };




    //--## Refresh Discovery parameters
    function refreshParameters(parameters){

            //-- Create option list accounts
            var accounts = [];
            parameters['accounts'].forEach( element => {
              accounts.push({ label: element, value: element });
            });
            setSelectedAccounts(accounts);
            accountList.current = accounts;

            //-- Create option list regions
            var regions = [];
            parameters['regions'].forEach( element => {
              regions.push({ label: element, value: element });
            });
            setSelectedRegions(regions);
            regionList.current = regions;

            //-- Create option list services
            var services = [];
            parameters['services'].forEach( element => {
              services.push({ label: element, value: element });
            });
            setSelectedServices(services);
            serviceList.current = services;

            //-- Create tag list
            var tags = [];
            parameters['tags'].forEach( element => {
              tags.push({ key: element['key'], value: element['value'] });
            });
            setSelectedTags(tags);
            tagList.current = tags;

            //-- Filters
            setSelectedFilter(parameters['filter']);
            filterList.current = parameters['filter'];

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




    //--## Get task information (for Table03 pre-fetching)
    async function fetchScanResults({ page, limit }){
          return new Promise((resolve, reject) => {
                try {
                      var parameters = {
                                      processId : 'metadata::api-001-get-metadata-results',
                                      scanId : currentScanId.current,
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
                            // Determine which log to update based on current step
                            if (currentStep.current === 2) {
                              setSearchLogs(response['content']);
                            } else if (currentStep.current === 3) {
                              setTaggingLogs(response['content']);
                            }
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




    //--## Start log polling
    function startLogPolling() {
      // Clear any existing interval
      if (searchLogInterval.current) {
        clearInterval(searchLogInterval.current);
      }

      // Start polling every 3 seconds
      searchLogInterval.current = setInterval(() => {
        getScanLogs(50);
      }, 3000);
    }




    //--## Stop log polling
    function stopLogPolling() {
      if (searchLogInterval.current) {
        clearInterval(searchLogInterval.current);
        searchLogInterval.current = null;
      }
      if (taggingLogInterval.current) {
        clearInterval(taggingLogInterval.current);
        taggingLogInterval.current = null;
      }
    }




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



    //--## Update resource action
    async function updateResourceAction(){
      try {
            // Check if resources are selected
            if (!selectedResources.current || selectedResources.current.length === 0) {
              showMessage({
                type: "warning",
                content: "Please select at least one resource to update."
              });
              return;
            }

            // Validate selection count doesn't exceed page size (safety check)
            if (selectedResources.current.length > pageSize.current) {
              showMessage({
                type: "error",
                content: `Error: Selection contains ${selectedResources.current.length} items but page size is ${pageSize.current}. Please refresh the page and try again.`
              });
              console.error('Selection count exceeds page size - this should not happen with page-scoped selection');
              return;
            }

            // Build array of resources to update
            const resourcesToUpdate = selectedResources.current.map(resource => ({
              scan_id: resource.scan_id,
              seq: resource.seq
            }));

            var parameters = {
                            processId : 'tagger::api-101-update-resource-action',
                            resources : resourcesToUpdate,
                            action : actionType.current
            };

            const api = createApiObject({ method : 'POST', async : true });
            api.onload = function() {
                      if (api.status === 200) {
                          var response = JSON.parse(api.responseText)?.['response'];
                          showMessage({
                            type: "success",
                            content: `Successfully updated ${response.updated_count} resource(s).`
                          });
                          // Clear selection
                          selectedResources.current = [];
                          setSelectedCount(0);
                          // Force table re-mount to refresh data
                          setTableKey(prev => prev + 1);
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: tagger::api-101-update-resource-action');
      }
    };




    //--## Check scan status and show appropriate message
    async function checkScanStatusAndShowMessage() {
      try {
        if (!currentScanId.current) return;

        var parameters = {
          processId: "metadata::api-003-get-metadata-search-status",
          scanId: currentScanId.current
        };

        const api = createApiObject({ method: 'POST', async: true });
        api.onload = function() {
          if (api.status === 200) {
            var response = JSON.parse(api.responseText)?.['response'];

            // Only show message if scan is completed
            if (response['status'] === 'completed') {
              if (response['has_errors']) {
                const metrics = response['metrics'];
                let detailMsg = '';
                if (metrics) {
                  detailMsg = ` (${metrics.tasks_success} successful, ${metrics.tasks_failed} failed out of ${metrics.tasks_total} tasks)`;
                }
                showMessage({
                  type: "warning",
                  content: `Search process ${currentScanId.current} completed with errors. Resources found (${response['resources']})${detailMsg}. Check logs for details.`
                });
              } else {
                const metrics = response['metrics'];
                let detailMsg = '';
                if (metrics) {
                  detailMsg = ` All ${metrics.tasks_total} tasks completed successfully.`;
                }
                showMessage({
                  type: "success",
                  content: `Search process ${currentScanId.current} has been completed. Resources found (${response['resources']}).${detailMsg}`
                });
              }
            }
          }
        };
        api.send(JSON.stringify({ parameters: parameters }));
      } catch (err) {
        console.log('Error checking scan status:', err);
      }
    }



    //--## Get Search Status
    const getMetadataSearchStatus = useCallback(async () => {

          try {
              // Check for timeout (10 minutes)
              if (searchStartTime.current && (Date.now() - searchStartTime.current > MAX_POLL_TIME)) {
                  setSearchStatus('timeout');
                  stopLogPolling();
                  getScanLogs(100); // Get final logs
                  showMessage({
                      type : "warning",
                      content : `Search process ${currentScanId.current} timed out after 10 minutes. Check logs for details.`
                  });
                  return;
              }

              var parameters = {
                              processId : "metadata::api-003-get-metadata-search-status",
                              scanId : currentScanId.current
              };

              const api = createApiObject({ method : 'POST', async : true });
              api.onload = function() {
                        if (api.status === 200) {
                            var response = JSON.parse(api.responseText)?.['response'];

                            if (response['status'] === 'completed') {
                                setSearchStatus('completed');
                                stopLogPolling(); // Stop polling when completed
                                getScanLogs(100); // Get final logs
                                pageId.current = 0;
                                // Force table to load with new scan data
                                setTableKey(prev => prev + 1);

                                // Check has_errors flag and show appropriate message
                                console.log('Has errors:', response['has_errors']); // Debug log
                                console.log('Metrics:', response['metrics']); // Debug log

                                if (response['has_errors']) {
                                    // Completed with errors
                                    const metrics = response['metrics'];
                                    let detailMsg = '';
                                    if (metrics) {
                                        detailMsg = ` (${metrics.tasks_success} successful, ${metrics.tasks_failed} failed out of ${metrics.tasks_total} tasks)`;
                                    }
                                    showMessage({
                                        type : "warning",
                                        content : `Search process ${currentScanId.current} completed with errors. Resources found (${response['resources']})${detailMsg}. Check logs for details.`
                                    });
                                } else {
                                    // Completed successfully
                                    const metrics = response['metrics'];
                                    let detailMsg = '';
                                    if (metrics) {
                                        detailMsg = ` All ${metrics.tasks_total} tasks completed successfully.`;
                                    }
                                    showMessage({
                                        type : "success",
                                        content : `Search process ${currentScanId.current} has been completed. Resources found (${response['resources']}).${detailMsg}`
                                    });
                                }

                            } else if (response['status'] === 'failed' || response['status'] === 'error') {
                                setSearchStatus('failed');
                                stopLogPolling();
                                getScanLogs(100); // Get final logs
                                showMessage({
                                    type : "error",
                                    content : `Search process ${currentScanId.current} failed. Check logs for details.`
                                });
                            } else {
                              // If the task is still pending, schedule another check
                              timeoutRef.current = setTimeout(getMetadataSearchStatus, 5000); // Check again after 5 seconds
                            }

                        }
              };
              api.send(JSON.stringify({ parameters : parameters }));

          } catch (err) {
            console.log('Timeout API error - PID: metadata::api-003-get-metadata-search-status');
            console.error(err);
          }
    }, []);




    //--## Get tagging status
    const getTaggingProcessStatus = useCallback(async () => {

      try {
          // Check for timeout (10 minutes)
          if (taggingStartTime.current && (Date.now() - taggingStartTime.current > MAX_POLL_TIME)) {
              setTaggingStatus('timeout');
              stopLogPolling();
              getScanLogs(100); // Get final logs
              showMessage({
                  type : "warning",
                  content : `Tagging process ${currentScanId.current} timed out after 10 minutes. Check logs for details.`
              });
              return;
          }

          var parameters = {
                          processId : 'tagger::api-103-get-tagging-process-status',
                          scanId : currentScanId.current
          };

          const api = createApiObject({ method : 'POST', async : true });
          api.onload = function() {
                    if (api.status === 200) {
                        var response = JSON.parse(api.responseText)?.['response'];

                        if (response['status'] === 'completed') {
                            setTaggingStatus('completed');
                            stopLogPolling(); // Stop polling when completed
                            getScanLogs(100); // Get final logs

                            // Use has_errors flag and metrics (new format)
                            const metrics = response['metrics'];
                            console.log('Tagging metrics:', metrics); // Debug log

                            if (response['has_errors']) {
                              // Completed with errors
                              let detailMsg = '';
                              if (metrics) {
                                detailMsg = ` (${metrics.success} successful, ${metrics.failed} failed out of ${metrics.total} resources)`;
                              }
                              showMessage({
                                type : "error",
                                content : (
                                  <>
                                      Tagging process {currentScanId.current} completed with errors{detailMsg}.
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
                            } else {
                              // Completed successfully
                              let detailMsg = '';
                              if (metrics) {
                                detailMsg = ` All ${metrics.total} resources tagged successfully.`;
                              }
                              showMessage({
                                type : "success",
                                content : `Tagging process ${currentScanId.current} has been completed.${detailMsg}`
                              });
                            }

                        } else if (response['status'] === 'failed' || response['status'] === 'error') {
                            setTaggingStatus('failed');
                            stopLogPolling();
                            getScanLogs(100); // Get final logs
                            showMessage({
                                type : "error",
                                content : `Tagging process ${currentScanId.current} failed. Check logs for details.`
                            });
                        } else {
                          timeoutRef.current = setTimeout(getTaggingProcessStatus, 5000);
                        }

                    }
          };
          api.send(JSON.stringify({ parameters : parameters }));

      } catch (err) {
        console.log('Timeout API error - PID: metadata::api-003-get-metadata-search-status');
        console.error(err);
      }
    }, []);




    //--## Create search process
    const handleCreateMetadataSearch = useCallback(() => {

          try {

                setDatasetResources([]);
                setSearchStatus("in-progress");
                setSearchLogs(""); // Clear previous logs
                searchStartTime.current = Date.now(); // Set start time for timeout tracking

                var scanId = ((new Date().toISOString().replace("T",".").substring(0, 19)).replaceAll(":","")).replaceAll("-","");
                currentScanId.current = scanId;

                var ruleset = JSON.parse(txtRuleset.current);
                ruleset['accounts'] = accountList.current;
                ruleset['regions'] = regionList.current;
                ruleset['services'] = serviceList.current;
                ruleset['tags'] = tagList.current;
                ruleset['action'] = actionTags.current;
                ruleset['filter'] = filterList.current;

                var parameters = {
                                processId : "metadata::api-002-create-metadata-search",
                                scanId : scanId,
                                name : "system-generated",
                                ruleset : ruleset,
                                action : 1,
                                type : 1
                };

                const api = createApiObject({ method : 'POST', async : true });
                api.onload = function() {
                          if (api.status === 200) {
                              var response = JSON.parse(api.responseText)?.['response'];
                              getMetadataSearchStatus();
                              startLogPolling(); // Start polling for logs
                          }
                };
                api.send(JSON.stringify({ parameters : parameters }));

          }
          catch(err){
                console.log(err);
                console.log('Timeout API error - PID: metadata::api-002-create-metadata-search');
          }

    }, [getMetadataSearchStatus]);




    //--## Start tagging process
    const handleStartTaggingProcess = useCallback(() => {

      try {

            setTaggingStatus("in-progress");
            setTaggingLogs(""); // Clear previous logs
            taggingStartTime.current = Date.now(); // Set start time for timeout tracking

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
                          startLogPolling(); // Start polling for logs
                      }
            };
            api.send(JSON.stringify({ parameters : parameters }));

      }
      catch(err){
            console.log(err);
            console.log('Timeout API error - PID: 05-create-tagging-process');
      }

    }, [getTaggingProcessStatus]);




    //--## Goto to main dashboard
    function handleGotoDashboard(){
      navigate('/dashboard');
    }




    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherProfiles();

        // Cleanup on unmount
        return () => {
          stopLogPolling();
        };
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
                              <Header variant="h1" description="Select a profile, configure tags, discover resources, and apply tagging actions across your AWS accounts.">
                                  Tagging process
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

                            //-- Block forward navigation if viewing excluded resources on step 2
                            if (activeStepIndex === 2 && detail.requestedStepIndex > activeStepIndex && selectedFilterAction?.value === "2") {
                              showMessage({ type: "warning", content: "Switch to 'Resources included' before proceeding to the next step." });
                              return;
                            }

                            //-- Block forward navigation if no included resources on step 2
                            if (activeStepIndex === 2 && detail.requestedStepIndex > activeStepIndex && selectedFilterAction?.value === "1" && totalRecords.current === 0) {
                              showMessage({ type: "error", content: "No resources included. Search for resources or move excluded resources back to included before proceeding." });
                              return;
                            }

                            setActiveStepIndex(detail.requestedStepIndex);
                            currentStep.current = detail.requestedStepIndex;

                            // Clear messages first
                            setApplicationMessage([]);

                            if (detail.requestedStepIndex == 1)
                            {
                              //gatherInventoryResources();
                            }
                            // Check for errors when navigating to step 2 (results view)
                            if (detail.requestedStepIndex == 1 && currentScanId.current) {
                              // Small delay to ensure message is shown after clear
                              setTimeout(() => checkScanStatusAndShowMessage(), 100);
                            }

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
                              title: "Select a profile",
                              description: "Choose a configuration profile that defines the scope of accounts, regions, services, and filtering rules for the tagging operation.",
                              content: (
                                        <Container>
                                                <table style={{"width":"100%"}}>
                                                  <tr>
                                                      <td valign="middle" style={{"width":"25%", "padding-right": "2em", "text-align": "center"}}>
                                                        <FormField label={"Profiles"}>
                                                            <Select
                                                                      selectedOption={selectedRuleSet}
                                                                      onChange={({ detail }) => {
                                                                        setSelectedRuleSet(detail.selectedOption);
                                                                        txtRuleset.current = detail.selectedOption['parameters'];
                                                                        refreshParameters(JSON.parse(detail.selectedOption['parameters']));
                                                                      }}
                                                                      options={datasetRuleSet}
                                                            />
                                                        </FormField>
                                                      </td>
                                                      <td valign="middle" style={{"width":"15%", "padding-right": "2em", "text-align": "left"}}>
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
                                                          <Header variant="h2" description="AWS accounts that will be scanned for resources.">
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
                                                          <Header variant="h2" description="AWS regions where resources will be discovered.">
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
                                                          <Header variant="h2" description="AWS service types to scan (e.g., ec2::Instance).">
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
                                                              <Header variant="h2" description="Conditions to narrow down discovered resources.">
                                                                  Advanced filtering
                                                              </Header>
                                                    }
                                                >
                                                      <WhereClauseBuilder01
                                                        value={selectedFilter}
                                                        readOnly={!customizeMode}
                                                        onChange={(newValue) => {
                                                            setSelectedFilter(newValue);
                                                            filterList.current = newValue;
                                                        }}
                                                      />
                                                </Container>

                                        </Container>
                              )
                            },
                            {
                              title: "Manage tags",
                              description: "Define the tag action (add or remove) and specify the tags to apply. These tags will be used during the tagging execution step.",
                              content: (
                                        <Container>
                                          <FormField label={"Action"}>
                                              <Select
                                                  selectedOption={selectedAction}
                                                  onChange={({ detail }) => {
                                                      setSelectedAction(detail.selectedOption);
                                                      actionTags.current = detail.selectedOption['value'];
                                                    }
                                                  }
                                                  options={[
                                                    { label: "Add tags", value: 1, iconName: "status-positive" },
                                                    { label: "Remove tags", value: 2, iconName: "status-negative" }
                                                  ]}
                                              />
                                              <br/>
                                          </FormField>
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
                              title: "Search resources",
                              description: "Scan AWS resources across the selected accounts and regions. Review discovered resources and choose which ones to include or exclude from the tagging operation.",
                              content: (
                                <div>
                                    <div className="custom-orange-button">
                                      <Button
                                            variant="primary"
                                            onClick={() => {
                                                    accountList.current =  selectedAccounts.map(obj => obj.value);
                                                    regionList.current =  selectedRegions.map(obj => obj.value);
                                                    serviceList.current =  selectedServices.map(obj => obj.value);
                                                    handleCreateMetadataSearch();
                                              }
                                            }
                                            disabled={(searchStatus=="in-progress" ? true : false )}
                                            loading={(searchStatus=="in-progress" ? true : false )}
                                      >
                                            Search resources
                                      </Button>
                                    </div>
                                    <br/>
                                    <Flashbar items={applicationMessage} />
                                    <br/>

                                    {/* ----### Loading Bar for Discovery */}
                                    {searchStatus === 'in-progress' && (
                                      <>
                                        <Container
                                          header={
                                            <Header
                                              variant="h3"
                                              description="Scanning AWS resources across accounts and regions"
                                            >
                                              Discovery in progress
                                            </Header>
                                          }
                                        >
                                          <SpaceBetween size="s">
                                            <LoadingBar
                                              variant="gen-ai"
                                            />
                                            <Box color="text-body-secondary" fontSize="body-s">
                                              <div>This may take several minutes depending on the number of accounts, regions, and services being scanned.</div>
                                              <div style={{ marginTop: '8px' }}>You can monitor the progress in the process logs below.</div>
                                              {searchLogs && (
                                                <div style={{ marginTop: '8px', fontStyle: 'italic' }}>
                                                  {searchLogs.split('\n')[0] || 'Initializing...'}
                                                </div>
                                              )}
                                            </Box>
                                          </SpaceBetween>
                                        </Container>
                                        <br/>
                                      </>
                                    )}

                                    {/* ----### Resource Search Results Table */}
                                    <Container>
                                        <CustomTable03
                                            key={tableKey}
                                            columnsTable={columnsTableResources}
                                            visibleContent={visibleContentResources}
                                            title={"Resource search results - " + currentScanId.current }
                                            description={""}
                                            fetchSize={fetchSize.current}
                                            displayPageSize={pageSize.current}
                                            totalRecords={totalRecords.current}
                                            selectionType="multi"
                                            onFetchData={fetchScanResults}
                                            onSelectionChange={( items ) => {
                                                // Store array of selected items
                                                selectedResources.current = items;
                                                // Update selection count for UI
                                                setSelectedCount(items.length);
                                              }
                                            }
                                            onPageChange={(pageInfo) => {
                                                console.log('Page changed:', pageInfo);
                                              }
                                            }
                                            loading={searchStatus=="in-progress"}
                                            footer={
                                              searchStatus !== 'idle' && (
                                                <ProcessLogs01
                                                  logs={searchLogs}
                                                  theme="dark"
                                                  headerText="Process logs"
                                                  defaultExpanded={false}
                                                  variant="footer"
                                                />
                                              )
                                            }
                                            extendedTableProperties={{
                                                variant : "borderless"
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
                                                                  // Clear selections when changing filter
                                                                  selectedResources.current = [];
                                                                  setSelectedCount(0);
                                                                  // Force table re-mount to fetch new data
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
                                                                  // Currently showing included, so move to excluded
                                                                  actionType.current = "2";
                                                                } else {
                                                                  // Currently showing excluded, so move to included
                                                                  actionType.current = "1";
                                                                }
                                                                updateResourceAction();
                                                              }}
                                                              disabled={selectedCount === 0}
                                                          >
                                                            {selectedFilterAction.value === "1"
                                                              ? `Move ${selectedCount > 0 ? selectedCount : ''} to excluded`.trim()
                                                              : `Move ${selectedCount > 0 ? selectedCount : ''} to included`.trim()}
                                                          </Button>

                                                        </SpaceBetween>
                                            }
                                          />

                                      </Container>
                                  </div>
                              )
                            },
                            {
                              title: "Launch tagging process",
                              description: "Review the summary and execute the tagging operation on all included resources. This action will modify tags on your AWS resources.",
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
                                                        {taggingLogs && (
                                                          <div style={{ marginTop: '8px', fontStyle: 'italic' }}>
                                                            {taggingLogs.split('\n')[0] || 'Initializing...'}
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
                                                  <ProcessLogs01
                                                    logs={taggingLogs}
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
                  extendedTableProperties={{
                      variant : "borderless"
                  }}
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
