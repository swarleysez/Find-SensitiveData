# Find-SensitiveData
PowerShell script to search a file share for potential sensitive data patterns

## Description

PowerShell script to search a file share for potential sensitive data patterns. Currently searches for patterns of:
- SSN
- Password
- Domain Prefix (Ex. MIDGAR\)
- AWS Keys (Access and Secret)
- MachineKey

## Usage

#### Default Execution
`Find-SensitiveData -SharePath <\\host\share>`

#### Overwrite any existing files with same name in current directory
`Find-SensitiveData -SharePath <\\host\share> -Force`

#### Save files to a different directory
`Find-SensitiveData -SharePath <\\host\share> -BaseDirectory <C:\Users\testuser1\Desktop>`

#### Cleanup existing files in current directory
`Remove-SensitiveData`

#### Cleanup existing files in different directory
`Remove-SensitiveData -BaseDirectory <C:\Users\testuser1\Desktop>`

## To-Do
- [ ] Add more patterns
- [ ] Add flexibility to multi-threading
- [ ] Add ability to find file shares to search through
- [ ] Limit searches to maximum file sizes based on extension
