import {useState,useEffect} from 'react'

//--## CloudScape components
import {
        AppLayout,
        SideNavigation,
        ContentLayout,
        Flashbar,
        Header,
        Box,
        Container,
        SpaceBetween,
        ColumnLayout,
        Grid,
        Button,
        Icon,
        Link
} from '@cloudscape-design/components';


//--## Functions
import { applicationVersionUpdate } from '../components/Functions';
import { configuration, SideMainLayoutHeader, SideMainLayoutMenu, breadCrumbs } from './Configs';


//--## Custom components
import CustomHeader from "../components/Header";



//--## Main function
function Home() {

    //-- Application messages
    const [versionMessage, setVersionMessage] = useState([]);

    //-- Navigation
    const [navigationOpen, setNavigationOpen] = useState(true);




    //--## Gather Version
    async function gatherVersion(){
        var appVersionObject = await applicationVersionUpdate({ codeId : "dbwcmp", moduleId: "home"} );
        if (appVersionObject.release > configuration["apps-settings"]["release"] ){
          setVersionMessage([
            {
              type: "info",
              content: "A new version is available with improved features and capabilities.",
              dismissible: true,
              dismissLabel: "Dismiss message",
              onDismiss: () => setVersionMessage([]),
              id: "message_1"
            }
          ]);
        }
    }



    //--## Initialization
    // eslint-disable-next-line
    useEffect(() => {
        gatherVersion();
    }, []);




    //--## Rendering
    return (
        <div style={{"background-color": "#f2f3f3"}}>
            <CustomHeader/>
            <AppLayout
                toolsHide
                breadCrumbs={breadCrumbs}
                navigation={<SideNavigation items={SideMainLayoutMenu} header={SideMainLayoutHeader} activeHref={"/"} />}
                navigationOpen={navigationOpen}
                onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
                disableContentPaddings={true}
                contentType="default"
                content={
                    <ContentLayout 
                        defaultPadding
                        headerVariant="high-contrast"
                        maxContentWidth={1024}
                        header={
                            <SpaceBetween size="m">
                                <Flashbar items={versionMessage} />
                                <Box variant="small">
                                    AWS Resource Management
                                </Box>
                                <Header
                                    variant="h1"
                                    description="Centralized tag management across accounts and regions"
                                >
                                    <span style={{ fontSize: '42px' }}>
                                        {configuration["apps-settings"]["application-title"]}
                                    </span>
                                </Header>
                                <Box variant="p">
                                    Automate tagging operations, build metadata inventories, and assess compliance across your AWS infrastructure. Discover resources across multiple accounts and regions, apply tags at scale, and gain visibility into tagging coverage.
                                </Box>
                            </SpaceBetween>
                        }
                    >

                        <SpaceBetween size="l">

                            {/* ----### Top row: Main description + sidebar */}
                            <Grid gridDefinition={[{ colspan: 7 }, { colspan: 5 }]}>

                                <SpaceBetween size="l">
                                    <Container>
                                        <SpaceBetween size="s">
                                            <Box variant="h2" fontSize="heading-m">Automated Tag Management</Box>
                                            <Box variant="p" color="text-body-secondary">
                                                Define tagging profiles and execute operations at scale. Discover resources and apply or remove tags with full visibility into results.
                                            </Box>
                                        </SpaceBetween>
                                    </Container>

                                    <ColumnLayout columns={2}>
                                        <Container>
                                            <SpaceBetween size="xs">
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    <Icon name="search" size="medium" />
                                                    <Box variant="h3">Tag Inventory</Box>
                                                </div>
                                                <Box variant="p" color="text-body-secondary">
                                                    Scan AWS resources to capture metadata and tag assignments across accounts and regions.
                                                </Box>
                                            </SpaceBetween>
                                        </Container>
                                        <Container>
                                            <SpaceBetween size="xs">
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    <Icon name="status-positive" size="medium" />
                                                    <Box variant="h3">Compliance Assessment</Box>
                                                </div>
                                                <Box variant="p" color="text-body-secondary">
                                                    Assess tagging compliance, identify gaps by service, and drive remediation workflows.
                                                </Box>
                                            </SpaceBetween>
                                        </Container>
                                    </ColumnLayout>
                                </SpaceBetween>


                                {/* ----### Right sidebar */}
                                <SpaceBetween size="l">
                                    <Container
                                        header={<Header variant="h2">Get started</Header>}
                                    >
                                        <SpaceBetween size="m">
                                            <Box variant="p">
                                                Define your tagging scope and launch a process from the dashboard.
                                            </Box>
                                            <Button variant="primary" href="/dashboard/">
                                                Open Dashboard
                                            </Button>
                                        </SpaceBetween>
                                    </Container>

                                    <Container
                                        header={<Header variant="h2">Quick links</Header>}
                                    >
                                        <SpaceBetween size="xs">
                                            <Link href="/tagger/" fontSize="body-m">Launch tagging process</Link>
                                            <Link href="/compliance/" fontSize="body-m">Compliance assessments</Link>
                                            <Link href="/metadata/bases/" fontSize="body-m">Metadata baselines</Link>
                                            <Link href="/profiles/" fontSize="body-m">Manage profiles</Link>
                                            <Link href="/modules/" fontSize="body-m">Service modules</Link>
                                        </SpaceBetween>
                                    </Container>

                                    <Container
                                        header={<Header variant="h2">Resources</Header>}
                                    >
                                        <SpaceBetween size="xs">
                                            <Link href="https://github.com/aws-samples/sample-tagger/" external fontSize="body-m">Documentation</Link>
                                            <Link href="https://github.com/aws-samples/sample-tagger/issues" external fontSize="body-m">Report an issue</Link>
                                        </SpaceBetween>
                                    </Container>
                                </SpaceBetween>

                            </Grid>


                            {/* ----### Capabilities section */}
                            <Container
                                header={
                                    <Header variant="h2" description="Core capabilities powering your tag management workflow.">
                                        Capabilities
                                    </Header>
                                }
                            >
                                <ColumnLayout columns={3} variant="text-grid">
                                    <SpaceBetween size="xs">
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <Icon name="settings" size="medium" />
                                            <Box variant="h3">Profile-Based Configuration</Box>
                                        </div>
                                        <Box variant="p" color="text-body-secondary">
                                            Reusable profiles that define target accounts, regions, services, and filters for consistent operations.
                                        </Box>
                                    </SpaceBetween>
                                    <SpaceBetween size="xs">
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <Icon name="multiscreen" size="medium" />
                                            <Box variant="h3">Cross-Account Operations</Box>
                                        </div>
                                        <Box variant="p" color="text-body-secondary">
                                            Tag and discover resources across multiple AWS accounts and regions in a single process.
                                        </Box>
                                    </SpaceBetween>
                                    <SpaceBetween size="xs">
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <Icon name="view-vertical" size="medium" />
                                            <Box variant="h3">Tag Explorer</Box>
                                        </div>
                                        <Box variant="p" color="text-body-secondary">
                                            Visualize tag distribution and drill down by service, account, or region to find gaps.
                                        </Box>
                                    </SpaceBetween>
                                    <SpaceBetween size="xs">
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <Icon name="file" size="medium" />
                                            <Box variant="h3">Extensible Service Modules</Box>
                                        </div>
                                        <Box variant="p" color="text-body-secondary">
                                            80+ AWS services supported via modular scripts. Easily extend with new service modules.
                                        </Box>
                                    </SpaceBetween>
                                    <SpaceBetween size="xs">
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <Icon name="filter" size="medium" />
                                            <Box variant="h3">Advanced Filtering</Box>
                                        </div>
                                        <Box variant="p" color="text-body-secondary">
                                            Target specific resources using filters on creation date, tags, name, or region.
                                        </Box>
                                    </SpaceBetween>
                                    <SpaceBetween size="xs">
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <Icon name="status-info" size="medium" />
                                            <Box variant="h3">Process Monitoring</Box>
                                        </div>
                                        <Box variant="p" color="text-body-secondary">
                                            Track operations with detailed logs, metrics, and resource-level results.
                                        </Box>
                                    </SpaceBetween>
                                </ColumnLayout>
                            </Container>

                        </SpaceBetween>

                    </ContentLayout>
                }
            />
        </div>
    );
}

export default Home;
