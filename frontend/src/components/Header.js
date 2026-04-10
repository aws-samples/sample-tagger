import { applyMode, Mode } from '@cloudscape-design/global-styles';
import { configuration } from '../pages/Configs';

//--## CloudScape components
import {
        TopNavigation,
        Header,        
} from '@cloudscape-design/components';



const i18nStrings = {
  searchIconAriaLabel: 'Search',
  searchDismissIconAriaLabel: 'Close search',
  overflowMenuTriggerText: 'More',
  overflowMenuTitleText: 'All',
  overflowMenuBackIconAriaLabel: 'Back',
  overflowMenuDismissIconAriaLabel: 'Close menu',
};

const profileActions = [      
      {
        type: 'menu-dropdown',
        id: 'preferences',
        text: 'Preferences',
        items: [
          { type: 'button', id: 'themeDark', text: 'Theme Dark' },
          { type: 'button', id: 'themeLight', text: 'Theme Light'},
        ]
      },
      {
        type: 'menu-dropdown',
        id: 'support-group',
        text: 'Support',
        items: [
          {id: 'documentation',text: 'Documentation'},          
          {id: 'version',text: 'Version (' + configuration["apps-settings"]?.["release"] + ')' || '-' },          
        ],
      }
];


export default function App() {
 
  
  const handleClickMenu = ({detail}) => {
                        
            switch (detail.id) {
              
              case 'themeDark':
                  applyMode(Mode.Dark);
                  localStorage.setItem("themeMode", "dark");
                  break;
                
              case 'themeLight':
                    applyMode(Mode.Light);
                    localStorage.setItem("themeMode", "light");
                    break;
                
              
            }

    };
    
  return (
    <div id="h" style={{ position: 'sticky', top: 0, zIndex: 1002 }}>
      <TopNavigation
        i18nStrings={i18nStrings}
        identity={{
          href: '/',
          title:  (
            <Header variant="h1">
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                <img src="/tag-icon.svg" alt="" style={{ width: '24px', height: '24px' }} />
                {configuration['apps-settings']['application-title']}
              </span>
            </Header>
          )
        }}
        utilities={[          
          { type: 'button', iconName: 'settings', title: 'Settings', ariaLabel: 'Settings', href : "/profiles/" },
          {
            type: 'menu-dropdown',
            text: 'IAM User',
            iconName: 'user-profile',
            items: profileActions,
            onItemClick : handleClickMenu
          }
        ]}
      />
    </div>
  );
}

