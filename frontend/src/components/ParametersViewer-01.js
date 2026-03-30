import { useState, useEffect } from 'react';

//--## CloudScape components
import {
    Container,
    Header,
    SpaceBetween
} from '@cloudscape-design/components';


//--## Custom components
import AccountEditorComponent from './AccountEditor-01';
import RegionEditorComponent from './RegionEditor-01';
import ServiceEditorComponent from './ServiceEditor-01';
import TagEditorComponent from './TagEditor-01';
import WhereClauseBuilder01 from './WhereClauseBuilder01';



//--## Main component
const ParametersViewer = ({ value = '{}' }) => {

    //-- Parsed parameters
    const [params, setParams] = useState({
        accounts: [],
        regions: [],
        services: [],
        tags: [],
        filter: ''
    });


    //--## Parse parameters when value changes
    useEffect(() => {
        try {
            const parsed = typeof value === 'string' ? JSON.parse(value) : value;
            setParams({
                accounts: parsed.accounts || [],
                regions: parsed.regions || [],
                services: parsed.services || [],
                tags: parsed.tags || [],
                filter: parsed.filter || ''
            });
        } catch (e) {
            setParams({ accounts: [], regions: [], services: [], tags: [], filter: '' });
        }
    }, [value]);


    //--## Rendering
    return (
        <SpaceBetween size="l">

            {/* ----### Accounts */}
            <Container header={<Header variant="h3">Accounts</Header>}>
                <AccountEditorComponent value={params.accounts} readOnly={true} />
            </Container>

            {/* ----### Regions */}
            <Container header={<Header variant="h3">Regions</Header>}>
                <RegionEditorComponent value={params.regions} readOnly={true} />
            </Container>

            {/* ----### Services */}
            <Container header={<Header variant="h3">Services</Header>}>
                <ServiceEditorComponent value={params.services} readOnly={true} />
            </Container>

            {/* ----### Tags */}
            <Container header={<Header variant="h3">Tags</Header>}>
                <TagEditorComponent value={params.tags} readOnly={true} />
            </Container>

            {/* ----### Advanced Filtering */}
            <Container header={<Header variant="h3">Advanced Filtering</Header>}>
                <WhereClauseBuilder01 value={params.filter} readOnly={true} />
            </Container>

        </SpaceBetween>
    );
};

export default ParametersViewer;
