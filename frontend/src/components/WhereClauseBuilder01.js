import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Button,
  FormField,
  Grid,
  Select,
  Input,
  SpaceBetween,
  Box,
  Header
} from '@cloudscape-design/components';
import WhereClauseViewer01 from './WhereClauseViewer01';
import {
  parseWhereClause,
  generateWhereClause,
  fieldOptions,
  getOperationOptions
} from './whereClauseUtils';

// Custom equality function for React.memo
function arePropsEqual(prevProps, nextProps) {
  return (
    prevProps.value === nextProps.value && 
    prevProps.readOnly === nextProps.readOnly
    // We intentionally don't compare onChange as it's a function that might change
    // between renders in the parent component
  );
}

const WhereClauseBuilder = React.memo(({ onChange, value = '', readOnly = false }) => {
  // Track if changes originated from this component
  const isInternalChangeRef = useRef(false);
  
  // Track previous value to detect changes
  const prevValueRef = useRef(value);
  
  // Initialize conditions state
  const [conditions, setConditions] = useState([]);
  
  // Effect to handle initial value and updates from parent
  useEffect(() => {
    // Skip if this change was initiated from inside the component
    if (isInternalChangeRef.current) {
      return;
    }
    
    // Only update if value actually changed
    if (prevValueRef.current !== value) {
      prevValueRef.current = value;
      
      const parsedConditions = parseWhereClause(value);
      
      if (parsedConditions.length > 0) {
        setConditions(parsedConditions);
      } else if (!readOnly) {
        // Add a default condition if none exist and not in read-only mode
        setConditions([{
          id: `default-\${Date.now()}`,
          field: 'creation_date',
          operation: '>',
          value: '',
          connector: 'AND'
        }]);
      } else {
        setConditions([]);
      }
    }
  }, [value, readOnly]);
  
  // Add default condition if none exist on first render
  useEffect(() => {
    if (conditions.length === 0 && !value && !readOnly) {
      setConditions([{
        id: `default-\${Date.now()}`,
        field: 'creation_date',
        operation: '>',
        value: '',
        connector: 'AND'
      }]);
    }
  }, []); // Only run once on mount
  
  // Add new condition
  const addCondition = useCallback(() => {
    isInternalChangeRef.current = true;
    setConditions(prevConditions => [
      ...prevConditions,
      {
        id: `new-\${Date.now()}`,
        field: 'creation_date',
        operation: '>',
        value: '',
        connector: 'AND'
      }
    ]);
  }, []);

  // Remove condition
  const removeCondition = useCallback((id) => {
    isInternalChangeRef.current = true;
    setConditions(prevConditions => prevConditions.filter(condition => condition.id !== id));
  }, []);

  // Update condition
  const updateCondition = useCallback((id, property, newValue) => {
    isInternalChangeRef.current = true;
    setConditions(prevConditions => 
      prevConditions.map(condition => {
        if (condition.id === id) {
          // Create a new condition object with the updated property
          const updatedCondition = { ...condition, [property]: newValue };
          
          // Special handling for field changes
          if (property === 'field') {
            // Set appropriate default operation based on the new field type
            updatedCondition.operation = newValue === 'creation_date' ? '>' : 'EXISTS';
            // Clear value when switching field types
            updatedCondition.value = '';
          }
          
          return updatedCondition;
        }
        return condition;
      })
    );
  }, []);
  
  // Effect to notify parent of WHERE clause changes - FIXED to prevent infinite loop
  useEffect(() => {
    // Only generate and notify if we have conditions and change was made internally
    if (isInternalChangeRef.current) {
      const newWhereClause = generateWhereClause(conditions);
      
      // Prevent infinite loops by checking if value actually changed
      if (newWhereClause !== value) {
        prevValueRef.current = newWhereClause;
        onChange(newWhereClause);
      }
      
      isInternalChangeRef.current = false;
    }
  }, [conditions, onChange, value]);
  
  return (
    <div>
      <SpaceBetween size="l">                
        {/* Form for modifying conditions */}        
        {!readOnly && (
          <>
            <Header variant="h3">Build Conditions</Header>
            
            {/* Headers for columns */}
            <Grid gridDefinition={[
              { colspan: 2 },
              { colspan: 3 },
              { colspan: 3 },
              { colspan: 3 },
              { colspan: 1 }
            ]}>
              <div></div>
              <Box fontWeight="bold">Field</Box>
              <Box fontWeight="bold">Operation</Box>
              <Box fontWeight="bold">Value</Box>
              <div></div>
            </Grid>
            
            {conditions.map((condition, index) => (
              <Grid
                key={condition.id}
                gridDefinition={[
                  { colspan: 2 },
                  { colspan: 3 },
                  { colspan: 3 },
                  { colspan: 3 },
                  { colspan: 1 }
                ]}
              >
                {/* Connector (AND/OR) */}
                {index > 0 ? (
                  <FormField label="">
                    <Select
                      selectedOption={{ label: condition.connector, value: condition.connector }}
                      onChange={({ detail }) => updateCondition(condition.id, 'connector', detail.selectedOption.value)}
                      options={[
                        { label: 'AND', value: 'AND' },
                        { label: 'OR', value: 'OR' }
                      ]}
                    />
                  </FormField>
                ) : (
                  <div></div> // Empty cell for first row
                )}
                
                {/* Field selection */}
                <FormField label="">
                  <Select
                    selectedOption={fieldOptions.find(option => option.value === condition.field) || fieldOptions[0]}
                    onChange={({ detail }) => {
                      updateCondition(condition.id, 'field', detail.selectedOption.value);
                    }}
                    options={fieldOptions}
                  />
                </FormField>
                
                {/* Operation selection */}
                <FormField label="">
                  <Select
                    selectedOption={
                      getOperationOptions(condition.field).find(op => op.value === condition.operation) || 
                      getOperationOptions(condition.field)[0]
                    }
                    onChange={({ detail }) => updateCondition(condition.id, 'operation', detail.selectedOption.value)}
                    options={getOperationOptions(condition.field)}
                  />
                </FormField>
                
                {/* Value input */}
                <FormField label="">
                  <Input
                    value={condition.value}
                    onChange={({ detail }) => updateCondition(condition.id, 'value', detail.value)}
                    placeholder={condition.field === 'creation_date' 
                      ? "e.g. 2023-04-01 18:00" 
                      : `Enter \${condition.field} value`}
                  />
                </FormField>
                
                {/* Remove condition button */}
                <Button 
                  iconName="remove"
                  onClick={() => removeCondition(condition.id)}
                  variant="icon"
                  ariaLabel="Remove condition"
                />
              </Grid>
            ))}
            
            {/* Add condition button */}
            <div>
              <Button 
                onClick={addCondition}
                iconName="add-plus"
              >
                Add Condition
              </Button>
            </div>
          </>
        )}

        {/* Use the WhereClauseViewer component for displaying the conditions in read-only mode */}
        {readOnly && <WhereClauseViewer01 value={value} />}
      </SpaceBetween>
    </div>
  );
}, arePropsEqual);

export default WhereClauseBuilder;