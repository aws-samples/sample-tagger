import { api } from './Api';

export const configuration = 
{
    "apps-settings": {
        "refresh-interval": 5*1000,      
        "api-url" : api["url"],          
        "release" : "0.1.0",
        "application-title": "Taggr Solution",
        "version-code-url" : "https://version.code.ds.wwcs.aws.dev/",
    },
    "colors": {
        "fonts" : {
            "metric102" : "#4595dd",
            "metric101" : "#e59400",
            "metric100" : "#e59400",
        },
        "lines" : {
            "separator100" : "#737c85",
            "separator101" : "#e7eaea",
        }
    }
    
};


export const SideMainLayoutHeader = { text: 'Resource Groups', href: '/' };

export const SideMainLayoutMenu = [
    {
      text: 'Metadata',
      type: 'section',
      defaultExpanded: true,
      items: [
          { type: "link", text: "Metadata Bases", href: "/metadata/bases/" },                    
      ],
    },
    {
        text: 'Tagging',
        type: 'section',
        defaultExpanded: true,
        items: [
            { type: "link", text: "Dashboard", href: "/dashboard/" },
            { type: "link", text: "Compliance", href: "/compliance/" },
            { type: "link", text: "Tagging process", href: "/tagger/" }
        ],
      },
    { type: "divider" },
    {
        text: 'Management',
        type: 'section',
        defaultExpanded: true,
        items: [
            { type: "link", text: "Profile", href: "/profiles/" },  
            { type: "link", text: "Modules", href: "/modules/" },      
        ],
      },
    { type: "divider" },
    {
          type: "link",
          text: "Documentation",
          href: "https://github.com/aws-samples/sample-tagger/",
          external: true,
          externalIconAriaLabel: "Opens in a new tab"
    }
     
  ];
  
  export const breadCrumbs = [{text: 'Service',href: '#',},{text: 'Resource search',href: '#',},];


export const tagEditorI18n = {
    keyPlaceholder: 'Enter key',
    valuePlaceholder: 'Enter value',
    addButton: 'Add new tag',
    removeButton: 'Remove',
    undoButton: 'Undo',
    undoPrompt: 'This tag will be removed upon saving changes',
    loading: 'Loading tags that are associated with this resource',
    keyHeader: 'Key',
    valueHeader: 'Value',
    optional: 'optional',
    keySuggestion: 'Custom tag key',
    valueSuggestion: 'Custom tag value',
    emptyTags: 'No tags associated with the resource.',
    tooManyKeysSuggestion: 'You have more keys than can be displayed',
    tooManyValuesSuggestion: 'You have more values than can be displayed',
    keysSuggestionLoading: 'Loading tag keys',
    keysSuggestionError: 'Tag keys could not be retrieved',
    valuesSuggestionLoading: 'Loading tag values',
    valuesSuggestionError: 'Tag values could not be retrieved',
    emptyKeyError: 'You must specify a tag key',
    maxKeyCharLengthError: 'The maximum number of characters you can use in a tag key is 128.',
    maxValueCharLengthError: 'The maximum number of characters you can use in a tag value is 256.',
    duplicateKeyError: 'You must specify a unique tag key.',
    invalidKeyError:
        'Invalid key. Keys can only contain Unicode letters, digits, white space and any of the following: _.:/=+@-',
    invalidValueError:
        'Invalid value. Values can only contain Unicode letters, digits, white space and any of the following: _.:/=+@-',
    awsPrefixError: 'Cannot start with aws:',
    tagLimit: (availableTags, tagLimit) =>
        availableTags === tagLimit
            ? 'You can add up to ' + tagLimit + ' tags.'
            : availableTags === 1
            ? 'You can add up to 1 more tag.'
            : 'You can add up to ' + availableTags + ' more tags.',
    tagLimitReached: (tagLimit) =>
        tagLimit === 1
            ? 'You have reached the limit of 1 tag.'
            : 'You have reached the limit of ' + tagLimit + ' tags.',
    tagLimitExceeded: (tagLimit) =>
        tagLimit === 1
            ? 'You have exceeded the limit of 1 tag.'
            : 'You have exceeded the limit of ' + tagLimit + ' tags.',
    enteredKeyLabel: (key) => 'Use "' + key + '"',
    enteredValueLabel: (value) => 'Use "' + value + '"',
};
