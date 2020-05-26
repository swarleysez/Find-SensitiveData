<#
	If you need to, here is the sensitive data finder code reduced to 1 line of syntax for PowerShell:

	PS:\> Get-ChildItem -Path '\\<host>\<share>' -Recurse -Include <*.txt> | Select-Object -ExpandProperty FullName | foreach {Select-String $_ -Pattern '<\bpassword\b( |=|:)>'} | Add-Content -Path '<.\passwords.txt>'
	
	This doesn't provide any of the convenience or optimization of the script but it's a lot faster to type or copy/paste
#>


function Get-FilePaths {

	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true,
			Position = 0)]
		[String]
		$SharePath,
		
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]
		$BaseDirectory = $env:USERPROFILE,

		[Parameter(Mandatory = $false)]
		[Switch]
		$Force
	)

	$CurrentUser = $env:USERNAME

	# If $BaseDirectory doesn't exist, then try to create it
	if ((Test-Path -Path $BaseDirectory) -eq $false)
	{
		try
		{
			$null = New-Item -Path $BaseDirectory -ItemType directory
		}
		catch
		{
			Write-Host -ForegroundColor red "[!] $((Get-Date).ToString('T')) : Unable to create $BaseDirectory"
			Return
		}
	}

	# Get root directory of specified $SharePath for use in output files
	$script:ShareRootDirectory = (($SharePath.Split('\'))[2..3]) -join '-'

	# Assign file structures
    $BaseOutputFile = $BaseDirectory + '\FilePaths-ALL-' + $ShareRootDirectory + '-' + $CurrentUser + '.csv'
    $script:DefaultOutputFile = $BaseDirectory + '\FilePaths-' + $ShareRootDirectory + '-' + $CurrentUser + '.csv'

    # If using -Force then delete previous CSV files
    if ($Force)
    {
        Remove-Item $BaseOutputFile -ErrorAction SilentlyContinue
        Remove-Item $DefaultOutputFile -ErrorAction SilentlyContinue
    }

    # Assign file existence tests
    $BaseFileExist = Test-Path -Path $BaseOutputFile
    $DefaultFileExist = Test-Path -Path $DefaultOutputFile
	
	# If using file doesn't exist, then start discovery process 
    if (!$DefaultFileExist)
	{
		# Recursively get ONLY files in provided path under 10MB in size, return the full path to each file, and write to current directory.
		# Write data to specified filename (Default = '.\FilePaths-$($ShareRootDirectory)-$($CurrentUser).txt') in current directory.
		Write-Output "[*] $((Get-Date).ToString('T')) : Recursively searching files in $SharePath and adding to $BaseOutputFile"
		
        if (!$BaseFileExist)
        {
            Get-ChildItem -Path $SharePath -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Extension,Length | Export-Csv -Path $BaseOutputFile -Delimiter ',' -Encoding UTF8
        }

		# Importing CSV, filtering, and assigning to $FilePaths array
		Write-Output "[*] $((Get-Date).ToString('T')) : Filtering files in $BaseOutputFile adding to the results to $DefaultOutputFile"

		$FilePaths = @()
		$FileExtensions = @('.txt','.xls','.csv','.bat','.ps1','.config','.cmd','.pem','.ppk','')
        $FileData = Import-Csv -Path $BaseOutputFile -Delimiter ','
                
        foreach ($File in $FileData)
        {
            # Filtering out unwanted file extensions and files larger than 10MB (had to convert System.Object to integer)
            if (($FileExtensions -contains $File.Extension) -and ([Int64]$File.Length -le 10000000))
            {
                $FilePaths += $File
            }
		}
		
		# Export filtered results to CSV
		$FilePaths | Export-Csv -Path $DefaultOutputFile -Delimiter ',' -Encoding UTF8
 	}
	elseif ($DefaultFileExist)
	{
		Write-Output "[-] $((Get-Date).ToString('T')) : File containing filepaths exists at $DefaultOutputFile. Using that file."
	}
}


function Find-SensitiveData {

	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true,
			Position = 0)]
		[String]
		$SharePath,
		
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]
		$BaseDirectory = $env:USERPROFILE,

		[Parameter(Mandatory = $false)]
		[Switch]
		$Force
	)
	
	
	$CurrentUser = $env:USERNAME
	
	# All patterns for matching (Ex. SSN, Passwords, etc.)
	$RegexPatterns = @{
		SSN 			= '\b\d{3}-\d{2}-\d{4}\b'
		Password 		= '(;|)(?i)\bpassword\b( |)=( |)'
		DomainPrefix	= "$env:USERDOMAIN\\"
		MachineKey		= '\bmachinekey\b'
		AWSAccessKey	= '\bAKIA[A-Z0-9]{16}\b'
		PrivateKey		= '\s*(\bBEGIN\b).*(PRIVATE KEY\b)\s*'
		#AWSSecret		= 'aws_secret_access_key'
	}
	
	# If $BaseDirectory doesn't exist, then try to create it
	if ((Test-Path -Path $BaseDirectory) -eq $false)
	{
		try
		{
			$null = New-Item -Path $BaseDirectory -ItemType directory
		}
		catch
		{
			Write-Host -ForegroundColor red "[!] $((Get-Date).ToString('T')) : Unable to create $BaseDirectory"
			Return
		}
	}

	# Execute 'Get-FilePaths' function to generate a list of files to search.

	if ($Force)
	{
		Write-Output "[!] $((Get-Date).ToString('T')) : '-Force' was used. Now removing previous data files"
        Get-FilePaths -SharePath $SharePath -BaseDirectory $BaseDirectory -Force
	}
	else
	{
		Get-FilePaths -SharePath $SharePath -BaseDirectory $BaseDirectory
	}

	# Get paths/files from generated $DefaultOutputFile.
	if (Test-Path $DefaultOutputFile)
	{
		# Import CSV
		$FilePaths = Import-Csv -Path $DefaultOutputFile -Delimiter ','
        
		# Loop through each $RegexPatterns
		foreach ($RegexPattern in $RegexPatterns.GetEnumerator())
		{
			Write-Output "[*] $((Get-Date).ToString('T')) : $($RegexPattern.Name) - Search started for pattern"

			# Remove previous data files
			$PreviousData = $BaseDirectory + "\PotentialData-" + $RegexPattern.Name + '-' + $ShareRootDirectory + '-' + $CurrentUser + '.txt'
			if (Test-Path -Path $PreviousData)
			{
				Remove-Item $PreviousData
			}

			# Region Runspace Pool
			[void][runspacefactory]::CreateRunspacePool()
			$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
			$RunspacePool = [runspacefactory]::CreateRunspacePool(
				1, # Minimum Runspaces to use
				[Int]$env:NUMBER_OF_PROCESSORS  # Maximum Runspaces to use
			)
			$RunspacePool.Open()
			
            # Do some trickery to get the proper BeginInvoke() method that allows for an output queue
            # From PowerView code
			$Method = $Null
			ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' })
			{
				$MethodParameters = $M.GetParameters()
				if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output')
				{
					$Method = $M.MakeGenericMethod([Object], [Object])
					break
				}
			}
			# End Region
			
			$Jobs = New-Object System.Collections.ArrayList

			# Loop over file path array using a maximum of 5 runspaces
			foreach ($FilePath in $FilePaths)
			{
				$ParameterList = @{
					ShareRootDirectory 	= $ShareRootDirectory
					RegexPatternValue 	= $RegexPattern.Value
					FilePath			= $FilePath
				}
							
				$PowerShell = [PowerShell]::Create()
				$PowerShell.RunspacePool = $RunspacePool
				
				# Execute scriptblock in runspace
				
				[void]$PowerShell.AddScript({
					Param(
						$FilePath,
						$ShareRootDirectory,
						$RegexPatternValue						
					)
				
                    # Search for regex pattern in file and select only the first match
                    $data = Select-String -Path $FilePath.FullName -Pattern $RegexPatternValue | Select-Object -First 1
                    if ($data)
                    {
                        $data
                    }
				})
				
				# Add the script parameters from $ParameterList that will be used in the runspace scriptblock
				[void]$PowerShell.AddParameters($ParameterList)

				########
				#	Code from PowerView to queue all scriptblock data so it can be output outside of runspace
				########
				
				# create the output queue
				$Output = New-Object Management.Automation.PSDataCollection[Object]

				# kick off execution using the BeginInvok() method that allows queues
				$Jobs += @{
					PS = $PowerShell
					Output = $Output
					Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
				}
			}
			
			Write-Verbose "[*] $((Get-Date).ToString('T')) : $($RegexPattern.Name) - Threads executing"

			# continuously loop through each job queue, consuming output as appropriate
			Do {
				ForEach ($Job in $Jobs)
				{
					# Slight modification to write all queue data to a text file
					$JobOutput = $Job.Output.ReadAll()
					
					if ($JobOutput)
					{
						$OutFile = "$($BaseDirectory)\PotentialData-$($RegexPattern.Name)-$($ShareRootDirectory)-$($CurrentUser).txt"
						Add-Content -Value $JobOutput -Path $OutFile
					}
				}
				Start-Sleep -Seconds 1
			}
			While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

			$SleepSeconds = 1
			Write-Verbose "[*] $((Get-Date).ToString('T')) : $($RegexPattern.Name) - Waiting $SleepSeconds seconds for final cleanup..."

			# cleanup- make sure we didn't miss anything
			for ($i=0; $i -lt $SleepSeconds; $i++)
			{
				ForEach ($Job in $Jobs)
				{
					# Slight modification to write all queue data to a text file
					$JobOutput = $Job.Output.ReadAll()
					
					if ($JobOutput)
					{
						$OutFile = "$($BaseDirectory)\PotentialData-$($RegexPattern.Name)-$($ShareRootDirectory)-$($CurrentUser).txt"
						Add-Content -Value $JobOutput -Path $OutFile
					}
					$Job.PS.Dispose()
				}
				Start-Sleep -S 1
			}

			$RunspacePool.Dispose()
			
			########
			#	End of code from PowerView
			########
			
			Write-Output "[*] $((Get-Date).ToString('T')) : $($RegexPattern.Name) - Search complete"

			<#
			This format would allow for the output to only display path/file and value that was matched. `n
			The potential issue with this is that there is no context on potential false positives; you `n
			would have to actually look at each file to know for certain.
			`$matched | foreach {Write-Output "$($_.Path) : $($_.matches.value)"}`
			#>
		}
	}
	else
	{
		Write-Warning "[!] $((Get-Date).ToString('T')) : No matching data found in $SharePath. Exiting..."
		Return
	}
	
	Write-Output "[*] $((Get-Date).ToString('T')) : That's All Folks!"
}

function Remove-SensitiveData {
	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $false)]
		[String[]]
		$DataFiles = @("PotentialData-*.txt","FilePaths-*.csv"),
		
		[Parameter(Mandatory = $false)]
		[String]
		$BaseDirectory = "$env:USERPROFILE"
		
	)
	
	
	# Cleanup files, if possible
	foreach ($DataFile in $DataFiles)
	{
		if (Test-Path $BaseDirectory\$DataFile)
		{
			Write-Output "[!] $((Get-Date).ToString('T')) : Removing $BaseDirectory\$DataFile"
			Remove-Item $BaseDirectory\$DataFile
		}
	}
}
