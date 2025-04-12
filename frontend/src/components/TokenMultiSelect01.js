import React, { useState, useEffect } from 'react';
import { FormField, Multiselect, TokenGroup } from '@cloudscape-design/components';

import TokenGroupReadOnly01 from './TokenGroupReadOnly01';

const TokenInput = ({
  label,
  value = [],
  onChange,
  readOnly = false,
  limit = 10,
  placeholder = '',
  errorText,
  description,
  options = [], // New prop for MultiSelect options
}) => {


  const MultiSelectI18n = {
      selectAllText: 'Select All'
  };



  // Convert input value to proper token format for internal use
  const normalizeInputValue = (inputVal) => {
    if (Array.isArray(inputVal)) {
      // Handle array of strings
      if (typeof inputVal[0] === 'string') {
        return inputVal.map(str => ({ label: str, value: str }));
      }
      // Already in correct format
      return inputVal;
    }
    // Empty case
    return [];
  };

  // Extract just the string values from tokens for onChange
  const extractTokenValues = (tokens) => {
    return tokens.map(token => token.value);
  };

  const [tokens, setTokens] = useState(normalizeInputValue(value));
  const [filteringText, setFilteringText] = useState('');
  
  // Update internal state when external value changes
  useEffect(() => {
    setTokens(normalizeInputValue(value));
  }, [value]);

  // Notify parent component of token changes
  const notifyChange = (updatedTokens) => {
    if (onChange) {
      // Use Cloudscape-style event format with detail object
      // But only pass the array of string values
      onChange({
        detail: {
          value: extractTokenValues(updatedTokens)
        }
      });
    }
  };

  // Handle MultiSelect changes
  const handleMultiSelectChange = ({ detail }) => {
    setTokens(detail.selectedOptions);
    notifyChange(detail.selectedOptions);
  };

  // Handle filtering text changes
  const handleFilteringChange = ({ detail }) => {
    setFilteringText(detail.filteringText);
  };

  // Create option from filtering text
  const createOption = () => {
    if (!filteringText.trim()) return;

    // Create a new option from the filtering text
    const newOption = { label: filteringText.trim(), value: filteringText.trim() };
    
    // Check if this option already exists to prevent duplicates
    if (!tokens.some(token => token.value === newOption.value)) {
      const updatedTokens = [...tokens, newOption];
      setTokens(updatedTokens);
      notifyChange(updatedTokens);
    }
    
    setFilteringText('');
  };

  // Handle token dismissal 
  const handleTokenDismiss = ({ detail: { itemIndex } }) => {
    const updatedTokens = [
      ...tokens.slice(0, itemIndex),
      ...tokens.slice(itemIndex + 1)
    ];
    setTokens(updatedTokens);
    notifyChange(updatedTokens);
  };
  
  // Generate list of available options - combine provided options with current tokens
  const allOptions = [...options];
  
  // Add "create new" option if text is entered
  const displayOptions = filteringText.trim() !== '' 
    ? [...allOptions, { label: `Create "${filteringText}"`, value: filteringText, disabled: false }] 
    : allOptions;

  return (
    <FormField 
      label={label}
      errorText={errorText}
      description={description}
    >
      {!readOnly && (
        <div>
            <Multiselect
              selectedOptions={tokens}
              options={displayOptions}
              onChange={handleMultiSelectChange}
              onFilteringChange={handleFilteringChange}
              filteringType="manual"
              filteringPlaceholder={placeholder}
              filteringText={filteringText}
              placeholder={placeholder}
              disabled={readOnly}
              selectedAriaLabel="Selected"          
              i18nStrings={MultiSelectI18n}                  
              enableSelectAll
            />           

        </div>
      )}

      {readOnly && (
        <div>
            <TokenGroupReadOnly01              
              items={tokens}
              limit={limit}            
            />
        </div>
      )}
    </FormField>
  );
};

export default TokenInput;