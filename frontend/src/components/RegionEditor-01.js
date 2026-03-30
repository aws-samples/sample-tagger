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
const RegionEditorComponent = ({
    value = [],
    readOnly = true,
    onChange,
    limit = 10
}) => {

    //-- Internal state
    const [regionOptions, setRegionOptions] = useState([]);
    const [selectedRegions, setSelectedRegions] = useState([]);
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
            setSelectedRegions(normalized);
        }
    }, [value]);


    //--## Initialize: set selected regions from value on mount
    useEffect(() => {
        setSelectedRegions(normalizeValue(value));
    }, []);


    //--## Fetch region catalog from API
    useEffect(() => {
        try {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', configuration["apps-settings"]["api-url"], true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.onload = function() {
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText)?.['response'];
                    const regions = (response['regions'] || []).map(r => ({ label: r, value: r }));
                    setRegionOptions(regions);
                }
            };
            xhr.send(JSON.stringify({
                parameters: { processId: 'profiles::api-205-get-profile-catalog' }
            }));
        } catch (err) {
            console.log('Error fetching region catalog:', err);
        }
    }, []);



    //--## Handle selection change
    const handleChange = ({ detail }) => {
        setSelectedRegions(detail.selectedOptions);
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
                items={selectedRegions}
                limit={limit}
            />
        );
    }

    return (
        <Multiselect
            selectedOptions={selectedRegions}
            options={regionOptions}
            onChange={handleChange}
            filteringType="auto"
            placeholder="Select regions"
            selectedAriaLabel="Selected"
            i18nStrings={{ selectAllText: 'Select All' }}
            enableSelectAll
        />
    );
};

export default RegionEditorComponent;
