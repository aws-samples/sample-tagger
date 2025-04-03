import {memo,useState,useEffect} from 'react';
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
                                                                
const Component = memo(({ label = "", value = "", disabled = false, onChange = () => {} }) => {

    
    // Variables
    const [valueInt, setValueInt] = useState('');
  
    function onChangeInt(value){
        setValueInt(value);
        onChange(value);
    }
    

    useEffect(() => {
          setValueInt(value);
    }, [value]);
    
    return (
              <div>
                  <FormField
                    label={label}
                  >
                    <Input
                      value={valueInt}
                      disabled={disabled}
                      onChange={event =>
                        onChangeInt(event.detail.value)
                      }
                    />
                  </FormField>
              </div>

           );
});

export default Component;
