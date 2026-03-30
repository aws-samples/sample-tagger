import React, { useState, useEffect } from 'react';
import { FormField, Input, TokenGroup } from '@cloudscape-design/components';
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
}) => {
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
  const [inputValue, setInputValue] = useState('');
  
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

  // Process input value and create tokens
  const processInput = (input) => {
    if (!input.trim()) return;

    const listValues = input.split(',');
    const newTokens = listValues
      .filter(item => item.trim() !== '')
      .map(item => ({ label: item.trim(), value: item.trim() }));

    if (newTokens.length > 0) {
      const updatedTokens = [...tokens, ...newTokens];
      setTokens(updatedTokens);
      notifyChange(updatedTokens);
      setInputValue('');
    }
  };

  // Handle input changes
  const handleInputChange = ({ detail }) => {
    setInputValue(detail.value);
  };

  // Handle key presses in input
  const handleKeyDown = ({ detail }) => {
    if (detail.keyCode === 13) { // Enter key
      processInput(inputValue);
    }
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

  // Handle input blur (optional: process input when focus leaves)
  const handleBlur = () => {
    processInput(inputValue);
  };

  return (
    <FormField 
      label={label}
      errorText={errorText}
      description={description}
    >
      {!readOnly && (
        <div>
            <Input
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              onBlur={handleBlur}
              value={inputValue}
              placeholder={placeholder}
              disabled={readOnly}
            />
            <TokenGroup
            onDismiss={readOnly ? undefined : handleTokenDismiss}
            items={tokens}
            limit={limit}            
            readOnly={readOnly}
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