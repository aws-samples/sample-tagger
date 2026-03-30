import { memo, useState, useEffect, useCallback } from 'react';
import CodeEditor from '@cloudscape-design/components/code-editor';
import 'ace-builds/css/ace.css';
import 'ace-builds/css/theme/cloud_editor.css';
import 'ace-builds/css/theme/cloud_editor_dark.css';

const i18nStrings = {
                    loadingState: 'Loading code editor',
                    errorState: 'There was an error loading the code editor.',
                    errorStateRecovery: 'Retry',
                    editorGroupAriaLabel: 'Code editor',
                    statusBarGroupAriaLabel: 'Status bar',
                    cursorPosition: (row, column) => `Ln \${row}, Col \${column}`,
                    errorsTab: 'Errors',
                    warningsTab: 'Warnings',
                    preferencesButtonAriaLabel: 'Preferences',
                    paneCloseButtonAriaLabel: 'Close',
                    preferencesModalHeader: 'Preferences',
                    preferencesModalCancel: 'Cancel',
                    preferencesModalConfirm: 'Confirm',
                    preferencesModalWrapLines: 'Wrap lines',
                    preferencesModalTheme: 'Theme',
                    preferencesModalLightThemes: 'Light themes',
                    preferencesModalDarkThemes: 'Dark themes',
};

const ComponentObject = memo(({ format = "javascript", value = "", height = 500, readOnly = true, header = null,  onChange = () => {} }) => {
    
        const [editorState, setEditorState] = useState({
              internalValue: value,
              preferences: {},
              loading: true,
              ace: null
        });

        useEffect(() => {
                let isMounted = true;
                async function loadAce() {
                  const aceModule = await import('ace-builds');
                  await import('ace-builds/webpack-resolver');
                  aceModule.config.set('useStrictCSP', true);
                  aceModule.config.set('readOnly', readOnly);
                  if (isMounted) {
                    setEditorState(prev => ({ ...prev, ace: aceModule, loading: false }));
                  }
                }

                loadAce();
                return () => { isMounted = false; };
        }, []);




        useEffect(() => {
                if (editorState.ace && editorState.ace.edit) {
                  const editor = editorState.ace.edit(document.querySelector('.ace_editor'));
                  if (editor) {
                    editor.setReadOnly(readOnly);
                  }
                }
        }, [editorState.ace, readOnly]);



        useEffect(() => {
                  setEditorState(prev => ({ ...prev, internalValue: value }));
        }, [value]);


        const handleDelayedChange = useCallback((event) => {
                    const newValue = event.detail.value;
                    setEditorState(prev => ({ ...prev, internalValue: newValue }));
                    onChange(newValue);
        }, [onChange]);

        const handlePreferencesChange = useCallback((event) => {
                    setEditorState(prev => ({ ...prev, preferences: event.detail }));
        }, []);


  return (
    <div>
      {header}
      <br />
      <CodeEditor
                ace={editorState.ace}
                value={editorState.internalValue}
                language={format}
                onDelayedChange={handleDelayedChange}
                preferences={editorState.preferences}
                onPreferencesChange={handlePreferencesChange}
                loading={editorState.loading}
                i18nStrings={i18nStrings}
                themes={{ light: ['cloud_editor'], dark: ['cloud_editor_dark'] }}
                editorContentHeight={height}
      />
    </div>
  );
});

export default ComponentObject;