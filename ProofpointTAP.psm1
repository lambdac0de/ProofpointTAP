<#
    This module contains PowerShell wrappers for Proofpoint's Targetted Attack Protection (TAP) Threat Insights (https://https://threatinsight.proofpoint.com) APIs
    The APIs are publicly documented here: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation
#>

# Get configuration file variables
$configPath = "$PSScriptRoot\config.json"
if (Test-Path $configPath) {
    $script:config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    $script:tap_base_url = $config.tap.uri.base
    $script:siem_url = $tap_base_url + $config.tap.uri.siem
    $script:forensics_url = $tap_base_url + $config.tap.uri.forensics
    $script:campaign_url = $tap_base_url + $config.tap.uri.campaign
    $script:urldecode_url = $tap_base_url + $config.tap.uri.urldecode
} else {
    throw "No configuration file found"
}

# Setup authentication header
if ([string]::IsNullOrWhiteSpace($config.credential.principal) -or [string]::IsNullOrWhiteSpace($config.credential.secret)) {
    Write-Warning "No or invalid authentication credential provided"
    $principal = Read-Host -Prompt "Enter API user principal"
    $secret = Read-Host -Prompt "Enter principal secret"
    $password_header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$principal`:$secret"))
}
else {
    $password_header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($config.credential.principal)`:$($config.credential.secret)"))
}
$TAP_Headers = @{'Accept'="application/json";
                 'Host'=$config.tap.host;
                 'Authorization'="Basic $password_header";}

# Definition of module functions
function Get-SIEMEvents {
    param(
        [Parameter(ParameterSetName="Date",Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [datetime]$StartDate,
        [Parameter(ParameterSetName="Date")]
        [ValidateNotNullOrEmpty()]
        [datetime]$EndDate = (Get-Date),
        [Parameter(ParameterSetName="Interval",Mandatory=$true)]
        [Int]$Minutes,
        [ValidateSet('Clicks Blocked','Clicks Permitted','Messages Blocked','Messages Delivered','Issues')]
        [string]$EventType,
        [ValidateSet('json','syslog')]
        [string]$Format = 'Json',
        [ValidateSet('url','attachment','messageText')]
        [string]$ThreatType,
        [ValidateSet('active','cleared','falsePositive')]
        [string]$ThreatStatus,
        [switch]$Raw
    )

    try {
        # determine target endpoint
        $rest_url = $siem_url
        if ($PSBoundParameters.ContainsKey('EventType')) {
            switch ($EventType) {
                'Clicks Blocked' {
                    $rest_url += '/clicks/blocked'
                    break
                }
                'Clicks Permitted' {
                    $rest_url += '/clicks/permitted'
                    break
                }
                'Messages Blocked' {
                    $rest_url += '/messages/blocked'
                    break
                }
                'Messages Delivered' {
                    $rest_url += '/messages/delivered'
                    break
                }
                'Issues' {
                    $rest_url += '/issues'
                    break
                }
                default {
                    $rest_url += '/all'
                }
            }
        }
        else {
            $rest_url += '/all'
        }

        # add required query parameters
        $rest_url += "?format=$Format"
        switch ($PSCmdlet.ParameterSetName) {
            'Date' {
                $dateStr = (Get-Date -Date $StartDate.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssZ") + '/' + (Get-Date -Date $EndDate.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssZ")
                $rest_url += "&interval=$dateStr"
                break
            }

            'Interval' {
                $dateSeconds = $Minutes * 60
                $rest_url += "&sinceSeconds=$dateSeconds"
                break
            }
            default {
                $dateStr = (Get-Date -Date (Get-Date).AddDays(-1).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssZ") + '/' + (Get-Date -Date $EndDate.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssZ")
                $rest_url += "&interval=$dateStr"
            }
        }

        # add optional query parameters
        if ($PSBoundParameters.ContainsKey('ThreatType')) {
            $rest_url += "&threatType=$ThreatType"
        }
        if ($PSBoundParameters.ContainsKey('ThreatStatus')) {
            $rest_url += "&threatStatus=$ThreatStatus"
        }

        # execute web request
        $result = Invoke-WebRequest -Uri $rest_url -UseBasicParsing -Method Get -Headers $TAP_Headers -UserAgent $user_agent -ErrorAction Stop
        
        if ($PSBoundParameters.ContainsKey('Raw')) {
            PrintRawOutput -Method GET -Url $rest_url -Response $result.Content
        } else {
            return ($result.Content | ConvertFrom-Json)
        }
    }
    catch {
        throw $_    
    }
}

function Get-ThreatForensics {
    param(
        [Parameter(ParameterSetName="Threat",Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ThreatID,
        [Parameter(ParameterSetName="Campaign",Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$CampaignID,
        [switch]$includeCampaignForensics,
        [switch]$Raw
    )

    try {
        $params = '?'
        switch ($PSCmdlet.ParameterSetName) {
            'Threat' {
                $params += "threatId=$ThreatID"
                if ($PSBoundParameters.ContainsKey('IncludeCampaignForensics')) {
                    $params += "&includeCampaignForensics=true"
                }
                break
            }
            'Campaign' {
                $params += "campaignId=$CampaignID"
                break
            }
            default {
                throw "Either ThreatID or CampaignID must be specified"
            }
        }

        $Url = ($forensics_url + $params)
        $result = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Get -Headers $TAP_Headers -UserAgent $user_agent -ErrorAction Stop

        if ($PSBoundParameters.ContainsKey('Raw')) {
            PrintRawOutput -Method GET -Url $Url -Response $result.Content
        } else {
            return ($result.Content | ConvertFrom-Json)
        }
    }
    catch {
        throw $_
    }
}

function Get-ThreatCampaign {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$CampaignID,
        [switch]$Raw
    )

    try {
        $Url = ($campaign_url + "/$CampaignID")
        $result = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Get -Headers $TAP_Headers -UserAgent $user_agent -ErrorAction Stop

        if ($PSBoundParameters.ContainsKey('Raw')) {
            PrintRawOutput -Method GET -Url $Url -Response $result.Content
        } else {
            return ($result.Content | ConvertFrom-Json)
        }
    }
    catch {
        throw $_
    }
}

function Get-DecodedUrl {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Urls,
        [switch]$Raw
    )

    try {
        $result = Invoke-WebRequest -Uri $urldecode_url -UseBasicParsing -Method Post -Headers $TAP_Headers -Body (@{'urls'=$Urls} | ConvertTo-Json -Compress) -ContentType "application/json" -UserAgent $user_agent -ErrorAction Stop

        if ($PSBoundParameters.ContainsKey('Raw')) {
            PrintRawOutput -Method POST -Url $urldecode_url -Body (@{'urls'=$Urls} | ConvertTo-Json)  -Response $result.Content
        } else {
            return ($result.Content | ConvertFrom-Json)
        }
    }
    catch {
        throw $_
    }
}
#############################