import { createTheme } from "@aws-amplify/ui-react";

export const AmplifyTheme = createTheme({
  name: 'cloudscape-theme',
  tokens: {
    colors: {
      brand: {
        primary: {
          10: { value: '#f1faff' },
          20: { value: '#d4f0ff' },
          40: { value: '#84cbff' },
          60: { value: '#16afff' },
          80: { value: 'rgb(255,144,39)' }, // CloudScape primary orange
          85: { value: '#0972d3' }, // CloudScape primary blue
          90: { value: '#033160' },
          100: { value: '#032b54' }
        }
      },
      background: {
        primary: { value: '#ffffff' },
        secondary: { value: 'rgba(255, 255, 255, 0.85)' } // Semi-transparent
      },
      border: {
        primary: { value: '#d1d5db' }, // CloudScape border color
        secondary: { value: '#e5e7eb' }
      }
    },
    components: {      
      button: {
        primary: {
          backgroundColor: { value: '{colors.brand.primary.80}' },
          color: { value: '#000000' },
          borderRadius: { value: '2px' } // CloudScape uses squared buttons
        }
      },
      input: {
        color: { value: '#000716' }, // CloudScape text color
        borderColor: { value: '{colors.border.primary}' },
        borderRadius: { value: '2px' }
      }      
    }
  }
});