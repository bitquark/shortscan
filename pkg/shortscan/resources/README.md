# Resources

## Wordlist

A custom wordlist was built for shortscan using data from the [GitHub dataset](https://console.cloud.google.com/marketplace/product/github/github-repos) hosted on BigQuery, which contains metadata from over 3 million GitHub repositories.

Included in the wordlist are files with extensions found in [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/aspnet/2wawkw1c(v=vs.100)) and default IIS config handler definitions. Also included are the most common directories in which these types of file were found where the directory name was used by more than ten projects. Finally, the wordlist is topped up with `raft-large-files.txt` and `raft-large-directories.txt` from the [raft](https://code.google.com/archive/p/raft/) project, providing good general coverage.

### Extensions

| Extension | Description | Files | Notes |
| --------- | ----------- | ----- | ----- |
| .aspx | ASP.NET web page | 9,571 |  |
| .ashx | Generic ASP.NET page with no UI | 609 |  |
| .ascx | Defines custom, reusable controls | 4,894 | Forbidden by default |
| .asax | Application startup and shutdown code | 5 | Forbidden by default |
| .asmx | Contains classes and methods available over SOAP | 589 |  |
| .axd | Manages site administration requests | 31 | Not Found by default |
| .browser | Used to identify browser features | 51 | Forbidden by default |
| .cd | Class diagram file | 897 | Forbidden by default |
| .compile | Precompiled stub file | 336 |  |
| .config | Contains XML defining ASP.NET features | 1,000 | Forbidden by default; Limited to top 1,000/19,608 |
| .cs | Class source compiled at run time | 1,000 | Forbidden by default; Limited to top 1,000/1,117,189 |
| .jsl | Class source compiled at run time | 95 | Forbidden by default |
| .vb | Class source compiled at run time | 1,000 | Forbidden by default; Limited to top 1,000/24,119 |
| .csproj | Visual Studio application project | 1,000 | Forbidden by default; Limited to top 1,000/95,112 |
| .vbproj | Visual Studio application project | 1,000 | Forbidden by default; Limited to top 1,000/3,071 |
| .vjsproj | Visual Studio application project | 8 | Forbidden by default |
| .disco | Contains XML defining available web services | 316 |  |
| .vsdisco | Contains XML defining available web services | 6 |  |
| .licx | License file | 2 | Forbidden by default |
| .webinfo | License file | 9 | Forbidden by default |
| .master | Defines web page layout | 403 | Forbidden by default |
| .mdb | Access database file | 1,000 | Forbidden by default; Limited to top 1,000/1,731 |
| .ldb | Access database file | 156 | Forbidden by default |
| .mdf | SQL Server Express database | 402 | Forbidden by default |
| .svc | Indigo Messaging Framework service file | 593 |  |
| .rem | Remoting handler file | 50 |  |
| .resources | Resource strings for localised images, text, etc. | 1,000 | Forbidden by default; Limited to top 1,000/9,688 |
| .resx | Resource strings for localised images, text, etc. | 1,000 | Forbidden by default; Limited to top 1,000/38,925 |
| .sdm | System definition model file | 3 | Forbidden by default |
| .sitemap | Contains information about site structure | 35 | Forbidden by default |
| .skin | Property settings for site formatting | 386 | Forbidden by default |
| .sln | Visual Web Developer solution file | 1,000 | Limited to top 1,000/39,285 |
| .soap | SOAP extension file | 32 |  |
| .asa | Application startup and shutdown code | 12 |  |
| .asp | ASP web page | 3060 |  |
| .cdx | Visual FoxPro compound index file | 78 |  |
| .cer | Certificate file | 994 |  |
| .idc | Internet Database Connector file | 88 |  |
| .shtm | Contains IIS server-side includes | 104 |  |
| .shtml | Contains IIS server-side includes | 1,350 |  |
| .stm | Contains IIS server-side includes | 24 |  |
| .wsdl | Defines service methods, data types, and endpoints | 6,867 |  |
| .xsd | Defines the structure, content, and data types of XML documents | 1,000 | Limited to top 1,000/35,392  |
| .lic | License file | 418 |  |
| .exclude | Visual Studio excluded file | 266 | Forbidden by default |
| .refresh | Visual Studio project dependency file | 191 | Forbidden by default |
| .edmx | Represents the database relationships and structure | 302 |  |
| .xamlx | Defines Windows Workflow Service endpoints | 2 |  |
| .cshtml | Razor view containing C# and HTML | 1,000 | Forbidden by default; Limited to top 1,000/18,685 |
| .vbhtml | Razor view containing Visual Basic and HTML | 67 | Forbidden by default |
| .ldf | SQL Server database log file | 412 | Forbidden by default |
