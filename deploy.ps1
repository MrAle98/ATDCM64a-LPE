
if ( (Get-PSDrive | ? { $_.Name -eq "X" }) -eq $null) {
	net use x: \\windows11\c$ pass /user:IEUser
}

cp x64\Release\DrvExpTemplate.exe x:\temp\


