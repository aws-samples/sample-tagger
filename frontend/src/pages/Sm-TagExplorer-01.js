import { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';

//--## CloudScape components
import {
  AppLayout,
  SideNavigation,
  ContentLayout,
  Container,
  Header,
  SpaceBetween,
  Flashbar,
  StatusIndicator,
  Box,
  TreeView,
  Icon,
  Link,
  Badge,
  Button,
  Modal
} from '@cloudscape-design/components';


//--## Functions
import { configuration, SideMainLayoutHeader, SideMainLayoutMenu } from './Configs';
import { createLabelFunction } from '../components/Functions';


//--## Custom components
import CustomHeader from "../components/Header";
import CustomTable01 from "../components/Table01";
import CustomTable03 from "../components/Table03";
import CodeEditor01 from '../components/CodeEditor01';



//--## Main function
function Application() {

    //-- URL parameters
    const [searchParams] = useSearchParams();
    const scanId = searchParams.get('scan_id');


    //-- Application messages
    const [applicationMessage, setApplicationMessage] = useState([]);
    const [navigationOpen, setNavigationOpen] = useState(false);


    //-- Tree view state
    const [loading, setLoading] = useState(true);
    const [treeItems, setTreeItems] = useState([]);
    const [totalResources, setTotalResources] = useState(0);
    const [expandedItems, setExpandedItems] = useState([]);


    //-- Table filter state
    const [selectedTagKey, setSelectedTagKey] = useState('');
    const [selectedTagValue, setSelectedTagValue] = useState('');
    const [selectedFilterAccount, setSelectedFilterAccount] = useState('');
    const [selectedFilterRegion, setSelectedFilterRegion] = useState('');
    const [showTable, setShowTable] = useState(false);


    //-- Table pagination refs
    const tableKey = useRef(0);
    const totalRecords = useRef(0);
    const fetchSize = useRef(100);
    const pageSize = useRef(20);
    const currentTagKey = useRef('');
    const currentTagValue = useRef('');
    const currentFilterAccount = useRef('');
    const currentFilterRegion = useRef('');


    //-- Table columns definition
    const columnsTable = [
        {id: 'account',    header: 'Account',    cell: item => item.account,    ariaLabel: createLabelFunction('account'),    sortingField: 'account'},
        {id: 'region',     header: 'Region',     cell: item => item.region,     ariaLabel: createLabelFunction('region'),     sortingField: 'region'},
        {id: 'service',    header: 'Service',    cell: item => item.service,    ariaLabel: createLabelFunction('service'),    sortingField: 'service'},
        {id: 'type',       header: 'Type',       cell: item => item.type,       ariaLabel: createLabelFunction('type'),       sortingField: 'type'},
        {id: 'identifier', header: 'Identifier', cell: item => item.identifier, ariaLabel: createLabelFunction('identifier'), sortingField: 'identifier'},
        {id: 'name',       header: 'Name',       cell: item => item.name,       ariaLabel: createLabelFunction('name'),       sortingField: 'name'},
        {id: 'creation',   header: 'Creation',   cell: item => item.creation,   ariaLabel: createLabelFunction('creation'),   sortingField: 'creation'},
        {id: 'tags_number', header: 'Tags', cell: item => (
            <a href='#;' style={{ "textDecoration": "none", "color": "inherit" }} onClick={() => showTags(item)}>
                <Badge color="blue">{item['tags_number']}</Badge>
            </a>
        ), ariaLabel: createLabelFunction('tags_number'), sortingField: 'tags_number'},
        {id: 'metadata', header: 'Metadata', cell: item => (
            <a href='#;' style={{ "textDecoration": "none", "color": "inherit" }} onClick={() => showMetadata(item)}>
                <Badge color="green">JSON</Badge>
            </a>
        ), ariaLabel: createLabelFunction('metadata'), sortingField: 'metadata'},
    ];
    const visibleTable = ['account', 'region', 'service', 'identifier', 'name', 'creation', 'tags_number', 'metadata'];


    //-- Modal Tags
    const [visibleShowTags, setVisibleShowTags] = useState(false);
    const columnsTableTags = [
        {id: 'key',   header: 'Key',   cell: item => item.key,   ariaLabel: createLabelFunction('key'),   sortingField: 'key', width: "250px"},
        {id: 'value', header: 'Value', cell: item => item.value, ariaLabel: createLabelFunction('value'), sortingField: 'value'},
    ];
    const visibleTableTags = ['key', 'value'];
    const [itemsTableTags, setItemsTableTags] = useState([]);


    //-- Modal Metadata
    const [visibleShowMetadata, setVisibleShowMetadata] = useState(false);
    const [metadata, setMetadata] = useState("");



    //--## Create API object
    function createApiObject({ method, async: isAsync }) {
        const xhr = new XMLHttpRequest();
        xhr.open(method, configuration["apps-settings"]["api-url"], isAsync);
        xhr.setRequestHeader("Authorization", `Bearer ${sessionStorage.getItem("x-token-cognito-authorization")}`);
        xhr.setRequestHeader("Content-Type", "application/json");
        return xhr;
    }



    //--## Show application message
    function showMessage({ type, content }) {
        setApplicationMessage([{
            type, content, dismissible: true, dismissLabel: "Dismiss message",
            onDismiss: () => setApplicationMessage([]), id: "message_1"
        }]);
    }



    //--## Fetch tag explorer data and build 4-level tree
    const fetchTagExplorerData = async () => {
        if (!scanId) {
            showMessage({ type: 'error', content: 'No scan_id provided' });
            setLoading(false);
            return;
        }
        setLoading(true);
        try {
            const api = createApiObject({ method: 'POST', async: true });
            api.onload = function() {
                if (api.status === 200) {
                    const response = JSON.parse(api.responseText);
                    const data = response.response;
                    setTotalResources(data.total);

                    //-- Build 4-level tree: Key -> Value -> Account -> Region
                    const items = Object.keys(data.tags).sort().map(key => {
                        const values = data.tags[key];
                        const keyTotal = Object.keys(values).reduce((sum, v) => v !== "Missing" ? sum + values[v].total : sum, 0);

                        const valueChildren = Object.keys(values).sort((a, b) => {
                            if (a === "Missing") return 1;
                            if (b === "Missing") return -1;
                            return values[b].total - values[a].total;
                        }).map(value => {
                            const vData = values[value];
                            const isMissing = value === "Missing";

                            //-- Account children, each with region sub-children
                            const accountChildren = Object.keys(vData.accounts || {}).sort().map(account => {
                                const acctData = vData.accounts[account];
                                const regionChildren = Object.keys(acctData.regions || {}).sort().map(region => ({
                                    id: `${key}::${value}::${account}::${region}`,
                                    nodeType: 'region',
                                    tagKey: key,
                                    tagValue: value,
                                    filterAccount: account,
                                    filterRegion: region,
                                    count: acctData.regions[region],
                                    content: `${region} (${acctData.regions[region]})`
                                }));

                                return {
                                    id: `${key}::${value}::${account}`,
                                    nodeType: 'account',
                                    tagKey: key,
                                    tagValue: value,
                                    filterAccount: account,
                                    filterRegion: '',
                                    count: acctData.total,
                                    content: `${account} (${acctData.total})`,
                                    children: regionChildren
                                };
                            });

                            return {
                                id: `${key}::${value}`,
                                nodeType: 'value',
                                tagKey: key,
                                tagValue: value,
                                tagName: value,
                                count: vData.total,
                                isMissing: isMissing,
                                content: `${value} (${vData.total})`,
                                children: accountChildren
                            };
                        });

                        return {
                            id: key,
                            nodeType: 'key',
                            content: `${key} (${keyTotal})`,
                            tagName: key,
                            children: valueChildren
                        };
                    });

                    setTreeItems(items);
                    setExpandedItems(items.map(item => item.id));
                    setLoading(false);
                } else {
                    showMessage({ type: 'error', content: `API error: ${api.status}` });
                    setLoading(false);
                }
            };
            api.onerror = function() {
                showMessage({ type: 'error', content: 'Network error while fetching tag explorer data' });
                setLoading(false);
            };
            api.send(JSON.stringify({
                parameters: { processId: 'metadata::api-010-get-tag-explorer-items', scanId: scanId }
            }));
        } catch (error) {
            showMessage({ type: 'error', content: `Error: ${error.message}` });
            setLoading(false);
        }
    };



    //--## Fetch filtered resources for Table03
    const fetchFilteredResources = async ({ page, limit }) => {
        try {
            const api = createApiObject({ method: 'POST', async: true });
            return new Promise((resolve, reject) => {
                api.onload = function() {
                    if (api.status === 200) {
                        const response = JSON.parse(api.responseText);
                        const data = response.response;
                        resolve({ resources: data.resources || [], totalRecords: data.records || 0 });
                    } else {
                        reject(new Error(`API error: ${api.status}`));
                    }
                };
                api.onerror = function() { reject(new Error('Network error')); };
                api.send(JSON.stringify({
                    parameters: {
                        processId: 'metadata::api-011-get-tag-explorer-items-filtered',
                        scanId: scanId,
                        tagKey: currentTagKey.current,
                        tagValue: currentTagValue.current,
                        filterAccount: currentFilterAccount.current,
                        filterRegion: currentFilterRegion.current,
                        page: page || 0,
                        limit: limit || 100
                    }
                }));
            });
        } catch (error) {
            return { resources: [], totalRecords: 0 };
        }
    };



    //--## Handle click on any count link in the tree
    const handleCountClick = (tagKey, tagValue, filterAccount, filterRegion) => {
        currentTagKey.current = tagKey;
        currentTagValue.current = tagValue;
        currentFilterAccount.current = filterAccount || '';
        currentFilterRegion.current = filterRegion || '';
        setSelectedTagKey(tagKey);
        setSelectedTagValue(tagValue);
        setSelectedFilterAccount(filterAccount || '');
        setSelectedFilterRegion(filterRegion || '');
        setShowTable(false);

        //-- Fetch total count first
        try {
            const api = createApiObject({ method: 'POST', async: true });
            api.onload = function() {
                if (api.status === 200) {
                    const response = JSON.parse(api.responseText);
                    totalRecords.current = response.response.records || 0;
                    setTimeout(() => {
                        tableKey.current = tableKey.current + 1;
                        setShowTable(true);
                    }, 10);
                }
            };
            api.send(JSON.stringify({
                parameters: {
                    processId: 'metadata::api-011-get-tag-explorer-items-filtered',
                    scanId, tagKey, tagValue,
                    filterAccount: filterAccount || '',
                    filterRegion: filterRegion || '',
                    page: 0, limit: 1
                }
            }));
        } catch (error) {
            console.error('Error fetching total:', error);
        }
    };



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
            api.onload = function () {
                if (api.status === 200) {
                    var response = JSON.parse(api.responseText)?.['response'];
                    setMetadata(JSON.stringify(JSON.parse(response['metadata']), null, 4));
                    setVisibleShowMetadata(true);
                }
            };
            api.send(JSON.stringify({ parameters: {
                processId: 'metadata::api-004-get-resource-metadata',
                scanId: item['scan_id'], seq: item['seq']
            }}));
        } catch (err) {
            console.log(err);
        }
    }



    //--## Render a clickable count link
    const renderCountLink = (count, tagKey, tagValue, filterAccount, filterRegion) => (
        <Link onFollow={(e) => { e.preventDefault(); handleCountClick(tagKey, tagValue, filterAccount, filterRegion); }}>
            {count}
        </Link>
    );



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        fetchTagExplorerData();
    }, [scanId]);



    //--## Rendering
    return (
        <div style={{"background-color": "#f2f3f3"}}>
            <CustomHeader/>
            <AppLayout
                navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/profiles/"} />}
                navigationOpen={navigationOpen}
                onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
                disableContentPaddings={true}
                contentType="dashboard"
                toolsHide={true}
                content={
                    <ContentLayout
                        defaultPadding
                        header={
                            <Header variant="h1" description="Analyze tag distribution and explore resources by tag key-value pairs across your AWS inventory.">
                                Tag Explorer ({scanId})
                            </Header>
                        }
                    >
                        <Flashbar items={applicationMessage} />

                        <table style={{"width":"100%"}}>
                            <tr>

                                {/* ----### Left Panel : Tag Distribution Tree */}
                                <td valign='top' style={{"width":"30%", "paddingRight": "1em"}}>
                                    <Container
                                        header={
                                            <Header variant="h2" description="Browse tag keys, values, accounts, and regions. Click a count to view matching resources." counter={`(${totalResources} total resources)`}>
                                                Tag Distribution
                                            </Header>
                                        }
                                    >
                                        {loading ? (
                                            <Box textAlign="center" padding="xxl">
                                                <StatusIndicator type="loading">Loading tag data...</StatusIndicator>
                                            </Box>
                                        ) : treeItems.length === 0 ? (
                                            <Box textAlign="center" padding="xxl">
                                                <StatusIndicator type="info">No tags found for this scan</StatusIndicator>
                                            </Box>
                                        ) : (
                                            <div role="region" tabIndex={0} aria-label="Scrollable tree-view container" style={{ overflowY: "auto", maxHeight: "600px" }}>
                                                <TreeView
                                                    items={treeItems}
                                                    expandedItems={expandedItems}
                                                    getItemId={(item) => item.id}
                                                    getItemChildren={(item) => item.children || []}
                                                    onItemToggle={({ detail }) => {
                                                        setExpandedItems(prev =>
                                                            detail.expanded ? [...prev, detail.item.id] : prev.filter(id => id !== detail.item.id)
                                                        );
                                                    }}
                                                    renderItem={(item) => {

                                                        //-- Key node
                                                        if (item.nodeType === 'key') {
                                                            return { content: (
                                                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                                                    <Badge color="blue">{item.tagName}</Badge>
                                                                    <span>({item.content.match(/\((\d+)\)/)?.[1] || 0})</span>
                                                                </span>
                                                            )};
                                                        }

                                                        //-- Value node
                                                        if (item.nodeType === 'value') {
                                                            const isMissing = item.isMissing;
                                                            return { content: (
                                                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                                                    <Icon name={isMissing ? "status-warning" : "status-positive"} variant={isMissing ? "warning" : "success"} />
                                                                    <Badge color="severity-neutral">{item.tagName}</Badge>
                                                                    <span>(</span>
                                                                    {renderCountLink(item.count, item.tagKey, item.tagValue, '', '')}
                                                                    <span>)</span>
                                                                </span>
                                                            )};
                                                        }

                                                        //-- Account node
                                                        if (item.nodeType === 'account') {
                                                            return { content: (
                                                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                                                    <span>{item.filterAccount} (</span>
                                                                    {renderCountLink(item.count, item.tagKey, item.tagValue, item.filterAccount, '')}
                                                                    <span>)</span>
                                                                </span>
                                                            )};
                                                        }

                                                        //-- Region node
                                                        if (item.nodeType === 'region') {
                                                            return { content: (
                                                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                                                    <span>{item.filterRegion} (</span>
                                                                    {renderCountLink(item.count, item.tagKey, item.tagValue, item.filterAccount, item.filterRegion)}
                                                                    <span>)</span>
                                                                </span>
                                                            )};
                                                        }

                                                        return { content: item.content };
                                                    }}
                                                    renderItemToggleIcon={({ expanded }) => (
                                                        <Icon size="small" name={expanded ? "treeview-collapse" : "treeview-expand"} />
                                                    )}
                                                    ariaLabel="Tag Explorer Tree"
                                                />
                                            </div>
                                        )}
                                    </Container>
                                </td>

                                {/* ----### Right Panel : Filters and Resource Table */}
                                <td valign='top' style={{"width":"70%"}}>
                                    {!selectedTagKey ? (
                                        <Container>
                                            <Box textAlign="center" padding="xxl">
                                                <StatusIndicator type="info">Click on a count number to view resources</StatusIndicator>
                                            </Box>
                                        </Container>
                                    ) : !showTable ? (
                                        <Container>
                                            <Box textAlign="center" padding="xxl">
                                                <StatusIndicator type="loading">Loading resources...</StatusIndicator>
                                            </Box>
                                        </Container>
                                    ) : (
                                        <SpaceBetween size="s">

                                            {/* ----### Applied Filters */}
                                            <Container
                                                header={
                                                    <Header variant="h2" description="Active filters applied to the resource list below.">
                                                        Applied Filters
                                                    </Header>
                                                }
                                            >
                                                <SpaceBetween direction="horizontal" size="xs">
                                                    <Button variant="primary">{selectedTagKey} = {selectedTagValue}</Button>
                                                    {selectedFilterAccount && <Button variant="primary">Account = {selectedFilterAccount}</Button>}
                                                    {selectedFilterRegion && <Button variant="primary">Region = {selectedFilterRegion}</Button>}
                                                </SpaceBetween>
                                            </Container>

                                            {/* ----### Resource Table */}
                                            <CustomTable03
                                                key={tableKey.current}
                                                columnsTable={columnsTable}
                                                visibleContent={visibleTable}
                                                title={"Resources"}
                                                description="Resources matching the selected tag filter."
                                                fetchSize={fetchSize.current}
                                                displayPageSize={pageSize.current}
                                                totalRecords={totalRecords.current}
                                                selectionType="single"
                                                onFetchData={fetchFilteredResources}
                                            />

                                        </SpaceBetween>
                                    )}
                                </td>

                            </tr>
                        </table>

                    </ContentLayout>
                }
            />


            {/* ----### Modal : Resource Tags */}
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


            {/* ----### Modal : Resource Metadata */}
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
                <CodeEditor01 format="json" value={metadata} readOnly={true} />
            </Modal>

        </div>
    );
}

export default Application;
