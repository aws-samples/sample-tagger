import { useState, useEffect, useRef } from 'react';

//--## CloudScape components
import {
    TagEditor
} from '@cloudscape-design/components';


//--## Custom components
import TokenGroupReadOnly01 from './TokenGroupReadOnly01';


//--## Tag Editor i18n strings
const defaultI18nStrings = {
    keyPlaceholder: 'Enter key',
    valuePlaceholder: 'Enter value',
    addButton: 'Add new tag',
    removeButton: 'Remove',
    undoButton: 'Undo',
    undoPrompt: 'This tag will be removed upon saving changes',
    loading: 'Loading tags',
    keyHeader: 'Key',
    valueHeader: 'Value',
    optional: 'optional',
    keySuggestion: 'Custom tag key',
    valueSuggestion: 'Custom tag value',
    emptyTags: 'No tags associated with the resource.',
    tooManyKeysSuggestion: 'Too many keys to display',
    tooManyValuesSuggestion: 'Too many values to display',
    keysSuggestionLoading: 'Loading tag keys',
    keysSuggestionError: 'Tag keys could not be retrieved',
    valuesSuggestionLoading: 'Loading tag values',
    valuesSuggestionError: 'Tag values could not be retrieved',
    emptyKeyError: 'You must specify a tag key',
    maxKeyCharLengthError: 'Max 128 characters for a tag key.',
    maxValueCharLengthError: 'Max 256 characters for a tag value.',
    duplicateKeyError: 'You must specify a unique tag key.',
    tagLimit: (availableTags, tagLimit) =>
        availableTags === tagLimit
            ? 'You can add up to ' + tagLimit + ' tags.'
            : availableTags === 1
            ? 'You can add up to 1 more tag.'
            : 'You can add up to ' + availableTags + ' more tags.',
    tagLimitReached: (tagLimit) =>
        'You have reached the limit of ' + tagLimit + ' tags.',
    tagLimitExceeded: (tagLimit) =>
        'You have exceeded the limit of ' + tagLimit + ' tags.',
    enteredKeyLabel: (key) => 'Use "' + key + '"',
    enteredValueLabel: (value) => 'Use "' + value + '"',
};


//--## Convert tags array to token items for read-only display
function convertTagsToTokens(tags) {
    if (!tags || tags.length === 0) return [];
    return tags.map((tag, index) => ({
        label: `${tag.key} = ${tag.value}`,
        dismissLabel: `Remove ${tag.key}`,
        value: String(index)
    }));
}



//--## Main component
const TagEditorComponent = ({
    value = [],
    readOnly = true,
    onChange,
    i18nStrings,
    limit = 10
}) => {

    //-- Internal state
    const [tags, setTags] = useState(value);
    const prevValueRef = useRef(value);


    //--## Sync internal state when external value changes
    useEffect(() => {
        const hasChanged =
            value.length !== prevValueRef.current.length ||
            JSON.stringify(value) !== JSON.stringify(prevValueRef.current);

        if (hasChanged) {
            prevValueRef.current = value;
            setTags(value);
        }
    }, [value]);



    //--## Handle tag changes from TagEditor
    const handleChange = ({ detail }) => {
        setTags(detail.tags);
        if (onChange) {
            onChange({ detail: { tags: detail.tags } });
        }
    };



    //--## Rendering
    if (readOnly) {
        return (
            <TokenGroupReadOnly01
                items={convertTagsToTokens(tags)}
                limit={limit}
            />
        );
    }

    return (
        <TagEditor
            i18nStrings={i18nStrings || defaultI18nStrings}
            tags={tags}
            onChange={handleChange}
            keysRequest={() => Promise.resolve([])}
            valuesRequest={() => Promise.resolve([])}
        />
    );
};

export default TagEditorComponent;
