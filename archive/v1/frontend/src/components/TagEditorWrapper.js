import React, { useState, useEffect, useRef } from 'react';
import { 
  TagEditor, 
  TokenGroup
} from '@cloudscape-design/components';

/**
 * TagEditorWrapper component
 */
const TagEditorWrapper = ({
  value = [],
  readOnly = false,
  onChange,
  placeholder = "Add new tag",
  i18nStrings,
  tagLimit
}) => {
  const [tags, setTags] = useState(value);
  
  // Use a ref to track if this is the initial render
  const isFirstRender = useRef(true);
  
  // Use a ref to compare previous value prop
  const prevValueRef = useRef(value);
  
  // Update internal state when external value prop changes
  useEffect(() => {
    // Skip the first render since we already set initial state
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }
    
    // Only update if the value has actually changed (deep comparison)
    const prevValue = prevValueRef.current;
    const hasChanged = 
      value.length !== prevValue.length || 
      JSON.stringify(value) !== JSON.stringify(prevValue);
    
    if (hasChanged) {
      prevValueRef.current = value;
      setTags(value);
    }
  }, [value]);

  // Transform tags to tokens for TokenGroup
  const getTokenItems = () => {
    return tags.map((tag, index) => ({
      label: `\${tag.key}:\${tag.value}`,
      dismissLabel: `Remove \${tag.key}`,
      value: String(index)
    }));
  };

  // Handle token removal in read-only mode
  const handleTokenDismiss = (tokenIndex) => {
    const index = parseInt(tokenIndex, 10);
    const newTags = [...tags];
    newTags.splice(index, 1);
    setTags(newTags);
    
    // Pass the event in the same format as TagEditor would
    if (onChange) {
      onChange({ detail: { tags: newTags } });
    }
  };

  return (
    <div>
      {readOnly ? (
        tags.length > 0 ? (
          <TokenGroup
            items={getTokenItems()}
            onDismiss={onChange ? handleTokenDismiss : undefined}
            alignment="horizontal"
          />
        ) : (
          <div style={{ color: '#666', fontStyle: 'italic' }}>No tags</div>
        )
      ) : (
        <TagEditor
          tags={tags}
          onChange={(event) => {
            setTags(event.detail.tags);
            if (onChange) {
              onChange(event); // Pass the entire event directly
            }
          }}
          keysRequest={() => Promise.resolve([])}
          valuesRequest={() => Promise.resolve([])}
          i18nStrings={{
            keyPlaceholder: i18nStrings?.keyPlaceholder || "Key",
            valuePlaceholder: i18nStrings?.valuePlaceholder || "Value",
            addButton: i18nStrings?.addButton || "Add new tag",
            removeButton: i18nStrings?.removeButton || "Remove",
            undoButton: i18nStrings?.undoButton || "Undo",
            undoPrompt: i18nStrings?.undoPrompt || "This tag will be removed upon saving",
            loading: "Loading tag keys",
            keyHeader: "Key",
            valueHeader: "Value",
            optional: "optional",
            keySuggestion: "Custom key",
            valueSuggestion: "Custom value",
            empty: i18nStrings?.empty || "No tags",
            tooManyKeysSuggestion: "Too many keys to display",
            tooManyValuesSuggestion: "Too many values to display",
            keysSuggestionLoading: "Loading tag keys",
            valuesSuggestionLoading: "Loading tag values",
            keysSuggestionError: "Error loading tag keys",
            valuesSuggestionError: "Error loading tag values",
            errorMessage: i18nStrings?.errorMessage,
            leadingError: "Duplicate key",
          }}
          tagLimit={tagLimit}
        />
      )}
    </div>
  );
};

export default TagEditorWrapper;