import React from 'react';
import { Alert, Box, Button, Container, Header, SpaceBetween } from '@cloudscape-design/components';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null, 
      errorInfo: null 
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Log error details
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    // Ignore ResizeObserver errors - they're benign
    if (error.message && 
        (error.message.includes('ResizeObserver') || 
         error.message.includes('ResizeObserver loop'))) {
      this.setState({ hasError: false });
      return;
    }
    
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
  }

  handleReset = () => {
    this.setState({ 
      hasError: false, 
      error: null, 
      errorInfo: null 
    });
    // Reload the page to reset the application state
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '2em', backgroundColor: '#f2f3f3', minHeight: '100vh' }}>
          <Container>
            <SpaceBetween size="l">
              <Header variant="h1">
                Something went wrong
              </Header>
              
              <Alert
                statusIconAriaLabel="Error"
                type="error"
                header="Application Error"
              >
                An unexpected error occurred. Please try refreshing the page.
              </Alert>

              {this.state.error && (
                <Box variant="code">
                  <strong>Error:</strong> {this.state.error.toString()}
                </Box>
              )}

              <Button 
                variant="primary" 
                onClick={this.handleReset}
              >
                Reload Application
              </Button>
            </SpaceBetween>
          </Container>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
