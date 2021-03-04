#prerequisites
New-Item -Path "c:\" -Name "VirusRemover" -ItemType "directory"
Remove-MpPreference -ExclusionPath "C:\System32\mue.exe" -Force
Remove-MpPreference -ExclusionPath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Force
#filters and consumers before
wmic /namespace:\\root\subscription PATH __EventFilter get/format:list > C:\VirusRemover\Filters.txt
wmic /namespace:\\root\subscription PATH __EventConsumer get/format:list > C:\VirusRemover\Consumers.txt
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding get/format:list > C:\VirusRemover\F_to_C_Binding.txt
Get-WmiObject -List -Namespace root\default > C:\VirusRemover\ClassesBeforeRemmedation.txt
(Get-WmiObject  -Namespace root\default -class "systemcore_Updater8" -List).GetText('mof') | Out-File C:\VirusRemover\WannaMineClass_CODE.txt

#WMI delete process 
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -filter "Name= 'SCM Event Log Filter'" |remove-WMIObject  -Verbose
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -filter "Name= 'SCM Event8 Log Filter'" |remove-WMIObject  -Verbose
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -filter "Name= 'SCM Event8 Log Filter2'" |remove-WMIObject  -Verbose
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -filter "Name= 'BVTFilter'" |remove-WMIObject  -Verbose
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding WHERE "Filter=""__EventFilter.Name='SCM Event8 Log Filter'""" DELETE
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding WHERE "Filter=""__EventFilter.Name='SCM Event Log Filter'""" DELETE
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding WHERE "Filter=""__EventFilter.Name='SCM Event8 Log Filter2'""" DELETE
wmic /NAMESPACE:"\\root\subscription" PATH __EventConsumer DELETE

#Consumers
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='SCM Event Log Consumer'" | Remove-WMIObject -Verbose
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='SCM Event8 Log Consumer'" | Remove-WMIObject -Verbose
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='SCM Event8 Log Consumer2'" | Remove-WMIObject -Verbose

#Droping the exploit class
Get-WmiObject -Namespace root\Default -List | where {$_.Name -eq 'systemcore_Updater8'} | Remove-WmiObject -Verbose

#rescann
wmic /namespace:\\root\subscription PATH __EventFilter get/format:list > C:\VirusRemover\Filters_Cleaned.txt
wmic /namespace:\\root\subscription PATH __EventConsumer get/format:list > C:\VirusRemover\Consumers_Cleaned.txt
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding get/format:list > C:\VirusRemover\F_to_C_Binding_Cleaned.txt
Get-WmiObject -List -Namespace root\default > C:\VirusRemover\ClassesAfterRemmedation.txt
