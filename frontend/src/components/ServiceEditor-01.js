import { useState, useEffect, useRef } from 'react';

//--## CloudScape components
import {
    Multiselect
} from '@cloudscape-design/components';


//--## Custom components
import TokenGroupReadOnly01 from './TokenGroupReadOnly01';


//--## Functions
import { configuration } from '../pages/Configs';



//--## Main component
const ServiceEditorComponent = ({
    value = [],
    readOnly = true,
    onChange,
    limit = 10
}) => {

    //-- Internal state
    const [serviceOptions, setServiceOptions] = useState([]);
    const [selectedServices, setSelectedServices] = useState([]);
    const prevValueRef = useRef(value);


    //--## Normalize value to token format
    const normalizeValue = (val) => {
        if (!Array.isArray(val)) return [];
        if (val.length > 0 && typeof val[0] === 'string') {
            return val.map(str => ({ label: str, value: str }));
        }
        return val;
    };


    //--## Sync internal state when external value changes
    useEffect(() => {
        const normalized = normalizeValue(value);
        const prevNormalized = normalizeValue(prevValueRef.current);
        const hasChanged =
            normalized.length !== prevNormalized.length ||
            JSON.stringify(normalized) !== JSON.stringify(prevNormalized);

        if (hasChanged) {
            prevValueRef.current = value;
            setSelectedServices(normalized);
        }
    }, [value]);


    //--## Initialize selected services from value on mount
    useEffect(() => {
        setSelectedServices(normalizeValue(value));
    }, []);


    //--## Fetch service catalog from API
    useEffect(() => {
        try {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', configuration["apps-settings"]["api-url"], true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.onload = function() {
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText)?.['response'];
                    const services = (response['services'] || []).map(s => ({ label: s, value: s }));
                    setServiceOptions(services);
                }
            };
            xhr.send(JSON.stringify({
                parameters: { processId: 'profiles::api-205-get-profile-catalog' }
            }));
        } catch (err) {
            console.log('Error fetching service catalog:', err);
        }
    }, []);



    //--## Handle selection change
    const handleChange = ({ detail }) => {
        setSelectedServices(detail.selectedOptions);
        if (onChange) {
            onChange({
                detail: {
                    value: detail.selectedOptions.map(opt => opt.value)
                }
            });
        }
    };



    //--## Rendering
    if (readOnly) {
        return (
            <TokenGroupReadOnly01
                items={selectedServices}
                limit={limit}
            />
        );
    }

    return (
        <Multiselect
            selectedOptions={selectedServices}
            options={serviceOptions}
            onChange={handleChange}
            filteringType="auto"
            placeholder="Select services"
            selectedAriaLabel="Selected"
            i18nStrings={{ selectAllText: 'Select All' }}
            enableSelectAll
        />
    );
};

export default ServiceEditorComponent;
