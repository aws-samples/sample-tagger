import { useState, useEffect, useRef } from 'react';

//--## CloudScape components
import {
    Input,
    TokenGroup
} from '@cloudscape-design/components';


//--## Custom components
import TokenGroupReadOnly01 from './TokenGroupReadOnly01';



//--## Main component
const AccountEditorComponent = ({
    value = [],
    readOnly = true,
    onChange,
    limit = 10,
    placeholder = "1234567890,0987654321"
}) => {

    //-- Internal state
    const [tokens, setTokens] = useState([]);
    const [inputValue, setInputValue] = useState('');
    const prevValueRef = useRef(value);


    //--## Normalize value to token format
    const normalizeValue = (val) => {
        if (!Array.isArray(val)) return [];
        if (val.length > 0 && typeof val[0] === 'string') {
            return val.map(str => ({ label: str, value: str }));
        }
        return val;
    };


    //--## Initialize tokens from value on mount
    useEffect(() => {
        setTokens(normalizeValue(value));
    }, []);


    //--## Sync internal state when external value changes
    useEffect(() => {
        const normalized = normalizeValue(value);
        const prevNormalized = normalizeValue(prevValueRef.current);
        const hasChanged =
            normalized.length !== prevNormalized.length ||
            JSON.stringify(normalized) !== JSON.stringify(prevNormalized);

        if (hasChanged) {
            prevValueRef.current = value;
            setTokens(normalized);
        }
    }, [value]);


    //--## Notify parent of changes
    const notifyChange = (updatedTokens) => {
        if (onChange) {
            onChange({
                detail: {
                    value: updatedTokens.map(t => t.value)
                }
            });
        }
    };



    //--## Process input and create tokens
    const processInput = (input) => {
        if (!input.trim()) return;
        const newTokens = input.split(',')
            .filter(item => item.trim() !== '')
            .map(item => ({ label: item.trim(), value: item.trim() }));

        if (newTokens.length > 0) {
            const updatedTokens = [...tokens, ...newTokens];
            setTokens(updatedTokens);
            notifyChange(updatedTokens);
            setInputValue('');
        }
    };



    //--## Handle token dismissal
    const handleTokenDismiss = ({ detail: { itemIndex } }) => {
        const updatedTokens = [
            ...tokens.slice(0, itemIndex),
            ...tokens.slice(itemIndex + 1)
        ];
        setTokens(updatedTokens);
        notifyChange(updatedTokens);
    };



    //--## Rendering
    if (readOnly) {
        return (
            <TokenGroupReadOnly01
                items={tokens}
                limit={limit}
            />
        );
    }

    return (
        <div>
            <Input
                onChange={({ detail }) => setInputValue(detail.value)}
                onKeyDown={({ detail }) => {
                    if (detail.keyCode === 13) processInput(inputValue);
                }}
                onBlur={() => processInput(inputValue)}
                value={inputValue}
                placeholder={placeholder}
            />
            <TokenGroup
                onDismiss={handleTokenDismiss}
                items={tokens}
                limit={limit}
            />
            <div style={{ color: '#687078', fontSize: '12px', marginTop: '4px' }}>
                Press Enter or use commas to add multiple accounts
            </div>
        </div>
    );
};

export default AccountEditorComponent;
