import { memo } from 'react';
import Container from "@cloudscape-design/components/container";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import CodeView from "@cloudscape-design/code-view/code-view";
import "ace-builds/css/ace.css";
import "ace-builds/css/theme/dawn.css";
import "ace-builds/css/theme/tomorrow_night_bright.css";

const ProcessLogsComponent = memo(({ 
    logs = 'Waiting for logs...', 
    theme = 'dark',
    headerText = 'Process logs',
    defaultExpanded = false,
    variant = 'footer'
}) => {
    
    // Use CodeView for better syntax highlighting and features
    return (
        <ExpandableSection
            headerText={headerText}
            variant={variant}
            defaultExpanded={defaultExpanded}
        >
            <Container>
                <CodeView
                    content={logs}
                    highlight={null} // No syntax highlighting for plain logs
                    lineNumbers={false}
                    wrapLines={false}
                    ariaLabel="Process logs"
                    themes={{
                        light: 'dawn',
                        dark: 'tomorrow_night_bright'
                    }}
                    theme={theme}
                />
            </Container>
        </ExpandableSection>
    );
});

export default ProcessLogsComponent;
