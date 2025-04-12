import React, { useState } from 'react';
import { Button, SpaceBetween } from '@cloudscape-design/components';

function CustomTokenGroup({ items =[], limit=10, onTokenClick }) {
  const [expanded, setExpanded] = useState(false);
  const hasMoreItems = items.length > limit;
  
  // Determine which items to display
  const displayedItems = expanded || !limit ? 
    items : 
    items.slice(0, limit);
  
  // Calculate how many more items are hidden
  const hiddenItemsCount = items.length - limit;
  
  return (
    <div className="custom-token-group-container">
      <SpaceBetween direction="horizontal" size="xs">
        {displayedItems.map((item, index) => (
          <CustomTokenButton 
            key={index} 
            label={item.label} 
            onClick={() => onTokenClick && onTokenClick(item, index)} 
          />
        ))}
        
        {/* "Show more" button when items exceed limit and not expanded */}
        {!expanded && hasMoreItems && (
          <Button
            variant="link"
            onClick={() => setExpanded(true)}
            formAction="none"
          >
            +{hiddenItemsCount} more
          </Button>
        )}
        
        {/* "Show less" button when expanded */}
        {expanded && hasMoreItems && (
          <Button
            variant="link"
            onClick={() => setExpanded(false)}
            formAction="none"
          >
            Show fewer
          </Button>
        )}
      </SpaceBetween>
    </div>
  );
}

// Using Button instead of Box for tokens
function CustomTokenButton({ label, onClick }) {
  return (
    <Button      
    >
      {label}
    </Button>
  );
}

// Default props
CustomTokenGroup.defaultProps = {
  limit: Infinity
};

export default CustomTokenGroup;