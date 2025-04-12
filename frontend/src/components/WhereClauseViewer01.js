import React, { useMemo } from 'react';
import TokenGroupReadOnly01 from './TokenGroupReadOnly01';
import { parseWhereClause, generateTokens, fieldOptions } from './whereClauseUtils';

// Custom equality function for React.memo
function arePropsEqual(prevProps, nextProps) {
  return prevProps.value === nextProps.value;
}

const WhereClauseViewer = React.memo(({ value = '' }) => {
  // Parse the WHERE clause string into conditions
  const conditions = useMemo(() => {
    return parseWhereClause(value);
  }, [value]);
  
  // Generate tokens from the parsed conditions
  const tokens = useMemo(() => {
    return generateTokens(conditions, fieldOptions);
  }, [conditions]);
  
  return (
    <TokenGroupReadOnly01
      items={tokens}                          
      limit={10}
    />
  );
}, arePropsEqual);

export default WhereClauseViewer;