import {
  Authenticator,
  Flex,
  Grid,
  useTheme,
  View,
  Heading,
  Text
} from "@aws-amplify/ui-react";

import Icon from "@cloudscape-design/components/icon";
import { configuration } from '../pages/Configs';

import { Navigate,useLocation } from "react-router-dom";

export default function Auth({children}) {

    const location = useLocation();
    const from = location.state?.from || "/";
    
    const { tokens } = useTheme();
    const components = {
      Header,
      SignIn: {
        Header: SignInHeader
      },
      Footer
    };


    function Header() {      
        return (
          <div>
              <Flex justifyContent="center">            
                
                <Heading level={2}>
                  <Icon
                    name="lock-private"
                    size="large"              
                  />
                  {configuration['apps-settings']['application-title']}                    
                </Heading>           
                
              </Flex>
              <br/>
          </div>
        );
    }
    
    
    function Footer() {
        const { tokens } = useTheme();
      
        return (
          <Flex justifyContent="center" padding={tokens.space.medium}>
            <Text></Text>
          </Flex>
        );
    }


    function SignInHeader() {
        const { tokens } = useTheme();
      
        return (
          <Heading level={4} padding={`${tokens.space.xl} ${tokens.space.xl} 0`}>
            Sign in 
          </Heading>
        );
    }


  return (
    <Grid templateColumns={{ base: "1fr 0", medium: "1fr 0fr" }}>
      <Flex
        
        justifyContent="center"
      >
        <Authenticator hideSignUp={true} components={components}>
          {({ signOut, user }) => (
            <main>
              <Navigate to={from} replace />;
            </main>
          )}
        </Authenticator>
      </Flex>
      <View height="100vh"
        
      >
      </View>
    </Grid>
  );
}
