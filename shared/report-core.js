(function(root,factory){
    if(typeof module==='object'&&module.exports){
        module.exports=factory();
    }else{
        root.ReportCore=factory();
    }
}(typeof self!=='undefined'?self:this,function(){
    var SCHEMA_VERSION='1.0.0';
    var CATEGORY_ORDER={security:0,architecture:1,maintainability:2};
    var SEVERITY_ORDER={critical:0,high:1,medium:2,low:3,info:4};
    var PRIORITY_ORDER={p0:0,p1:1,p2:2,p3:3};

    function hash(input){
        var str=String(input||'');
        var h=2166136261;
        for(var i=0;i<str.length;i++){
            h^=str.charCodeAt(i);
            h+=(h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24);
        }
        return (h>>>0).toString(16);
    }

    function toArray(value){return Array.isArray(value)?value:[];}
    function toPathArray(value){
        return toArray(value).map(function(v){
            if(typeof v==='string')return v;
            if(v&&typeof v==='object')return v.file||v.path||v.name||'';
            return '';
        }).filter(Boolean);
    }

    function normalizeSeverity(raw){
        var v=String(raw||'').toLowerCase();
        if(v==='critical'||v==='high'||v==='medium'||v==='low'||v==='info')return v;
        if(v==='warning')return'medium';
        if(v==='error')return'high';
        return'info';
    }

    function normalizePriority(severity){
        var s=normalizeSeverity(severity);
        if(s==='critical')return'p0';
        if(s==='high')return'p1';
        if(s==='medium')return'p2';
        return'p3';
    }

    function healthGrade(score){
        if(score>=90)return'A';
        if(score>=80)return'B';
        if(score>=70)return'C';
        if(score>=60)return'D';
        return'F';
    }

    function calcHealthFromData(data){
        if(!data||!data.stats)return{score:0,grade:'F'};
        var score=100;
        var deadPct=data.stats.functions>0?(data.stats.dead/data.stats.functions*100):0;
        score-=Math.min(20,deadPct);
        var issues=toArray(data.issues);
        var circular=issues.filter(function(i){return String(i.title||'').includes('Circular');}).length;
        score-=Math.min(20,circular*5);
        var god=issues.filter(function(i){return String(i.title||'').includes('Large');}).length;
        score-=Math.min(15,god*3);
        var avgCoup=data.stats.files>0?(data.stats.connections/data.stats.files):0;
        score-=Math.min(15,Math.max(0,avgCoup-3)*2);
        var sec=toArray(data.securityIssues).filter(function(i){return i&&i.severity==='high';}).length;
        score-=Math.min(20,sec*5);
        score=Math.max(0,Math.round(score));
        return{score:score,grade:healthGrade(score)};
    }

    function stableId(prefix,parts){
        return prefix+'_'+hash(parts.join('|')).slice(0,12);
    }

    function createRawReportFromUI(input){
        var data=input&&input.data?input.data:null;
        var repoInfo=input&&input.repoInfo?input.repoInfo:null;
        var isLocal=!!(input&&input.isLocal);
        if(!data)return null;
        var h=calcHealthFromData(data);
        var repo=repoInfo?(isLocal?'Local Folder':repoInfo.owner+'/'+repoInfo.repo):'Unknown Repository';
        return{
            repository:repo,
            analyzedAt:(input&&input.analyzedAt)||new Date().toISOString(),
            codeflowVersion:'1.0',
            summary:{
                healthScore:h.score,
                healthGrade:h.grade,
                totalFiles:data.stats.files,
                totalFunctions:data.stats.functions,
                totalConnections:data.stats.connections,
                linesOfCode:data.stats.loc,
                unusedFunctions:data.stats.dead,
                securityIssues:toArray(data.securityIssues).length,
                patterns:toArray(data.patterns).length,
                duplicates:data.stats.duplicates||0,
                layerViolations:data.stats.violations||0,
                highSecurityIssues:data.stats.security||0
            },
            files:toArray(data.files).map(function(f){
                var fns=toArray(f.functions).map(function(fn){
                    var st=data.fnStats?data.fnStats[fn.name]:null;
                    return{
                        name:fn.name,
                        line:fn.line,
                        internalCalls:st?st.internal:0,
                        externalCalls:st?st.external:0,
                        totalCalls:st?(st.internal+st.external):0,
                        isUnused:st?(st.internal+st.external===0):true,
                        isExported:st?st.isExported:false,
                        isClassMethod:st?st.isClassMethod:false,
                        isTopLevel:st?st.isTopLevel:true,
                        type:st?st.type:'function',
                        callers:st&&st.callers?st.callers.map(function(c){return{file:c.file,name:c.name,count:c.count};}):[],
                        code:fn.code
                    };
                });
                return{
                    path:f.path,
                    name:f.name,
                    folder:f.folder,
                    layer:f.layer,
                    lines:f.lines,
                    churn:f.churn||0,
                    isCode:f.isCode!==false,
                    functions:fns,
                    functionCount:toArray(f.functions).length
                };
            }),
            unusedFunctions:toArray(data.deadFunctions).map(function(fn){return{name:fn.name,file:fn.file,folder:fn.folder,line:fn.line,codeLines:fn.codeLines,code:fn.code,extension:fn.ext};}),
            dependencies:toArray(data.connections).map(function(c){
                var src=typeof c.source==='object'?c.source.id:c.source;
                var tgt=typeof c.target==='object'?c.target.id:c.target;
                return{from:src,to:tgt,function:c.fn,callCount:c.count};
            }),
            architectureIssues:toArray(data.issues).map(function(i){return{type:i.type,title:i.title,description:i.desc,affectedFiles:i.items?i.items.map(function(x){return x.file||x.name;}):[],affectedItems:i.items||[]};}),
            patterns:toArray(data.patterns).map(function(p){return{name:p.name,description:p.desc,isAntiPattern:p.isAnti||false,severity:p.severity||'info',icon:p.icon||'',files:toArray(p.files).map(function(f){return f.path||f.name;}),fileDetails:p.files||[],metrics:p.metrics||{}};}),
            securityIssues:toArray(data.securityIssues).map(function(s){return{severity:s.severity,title:s.title,description:s.desc,file:s.file,path:s.path,line:s.line,code:s.code};}),
            duplicates:data.duplicates||[],
            layerViolations:data.layerViolations||[],
            suggestions:data.suggestions||[],
            languageBreakdown:data.stats.languages||[],
            folderStructure:data.folders||[],
            functionStatistics:Object.keys(data.fnStats||{}).map(function(fnName){
                var st=data.fnStats[fnName];
                return{name:fnName,file:st.file,folder:st.folder,line:st.line,internalCalls:st.internal,externalCalls:st.external,totalCalls:st.count||(st.internal+st.external),isExported:st.isExported,isClassMethod:st.isClassMethod,isTopLevel:st.isTopLevel,type:st.type,callers:st.callers?st.callers.map(function(c){return{file:c.file,name:c.name,count:c.count};}):[],code:st.code};
            })
        };
    }

    function normalizeReport(rawReport){
        if(!rawReport)throw new Error('raw report is required');
        var reportId=stableId('report',[rawReport.repository,rawReport.analyzedAt,rawReport.codeflowVersion,rawReport.summary&&rawReport.summary.totalFiles]);
        var architecture=toArray(rawReport.architectureIssues).map(function(i,idx){
            var severity=normalizeSeverity(i.type==='critical'?'high':(i.type||'medium'));
            return{
                id:stableId('arch',[i.title,idx,rawReport.repository]),
                category:'architecture',
                subtype:'architecture_issue',
                severity:severity,
                priority:normalizePriority(severity),
                title:i.title,
                description:i.description||'',
                targetFiles:toPathArray(i.affectedFiles),
                payload:i
            };
        });
        var security=toArray(rawReport.securityIssues).map(function(s,idx){
            var severity=normalizeSeverity(s.severity||'medium');
            return{
                id:stableId('sec',[s.title,s.path,s.line,idx]),
                category:'security',
                subtype:'security_issue',
                severity:severity,
                priority:normalizePriority(severity),
                title:s.title,
                description:s.description||'',
                targetFiles:toPathArray([s.path||s.file]),
                payload:s
            };
        });
        var deadCode=toArray(rawReport.unusedFunctions).map(function(fn,idx){
            var severity='low';
            return{
                id:stableId('dead',[fn.name,fn.file,fn.line,idx]),
                category:'maintainability',
                subtype:'unused_function',
                severity:severity,
                priority:normalizePriority(severity),
                title:'Unused function: '+fn.name,
                description:'Function appears unreferenced and may be dead code.',
                targetFiles:toPathArray([fn.file]),
                payload:fn
            };
        });
        var duplicates=toArray(rawReport.duplicates).map(function(d,idx){
            var severity=normalizeSeverity(d.type==='code'?'medium':'low');
            return{
                id:stableId('dup',[d.type,d.name,idx]),
                category:'maintainability',
                subtype:d.type==='code'?'duplicate_code':'duplicate_name',
                severity:severity,
                priority:normalizePriority(severity),
                title:d.type==='code'?'Duplicate code block':'Duplicate function name: '+(d.name||'unknown'),
                description:d.suggestion||'Duplicate implementation detected.',
                targetFiles:toPathArray(d.files),
                payload:d
            };
        });
        var layerViolations=toArray(rawReport.layerViolations).map(function(v,idx){
            var severity='high';
            return{
                id:stableId('layer',[v.from,v.to,v.fn,idx]),
                category:'architecture',
                subtype:'layer_violation',
                severity:severity,
                priority:normalizePriority(severity),
                title:'Layer violation: '+(v.fromLayer||'unknown')+' -> '+(v.toLayer||'unknown'),
                description:v.suggestion||'Lower layer imports a higher layer.',
                targetFiles:toPathArray([v.from,v.to]),
                payload:v
            };
        });
        var suggestions=toArray(rawReport.suggestions).map(function(s,idx){
            var severity=normalizeSeverity(s.priority==='high'?'high':(s.priority==='medium'?'medium':'low'));
            return{
                id:stableId('sug',[s.title,s.action,idx]),
                severity:severity,
                priority:normalizePriority(severity),
                title:s.title||'Suggestion',
                description:s.desc||'',
                action:s.action||'',
                impact:s.impact||''
            };
        });

        var allFindings=[].concat(security,architecture,layerViolations,duplicates,deadCode).sort(function(a,b){
            if(CATEGORY_ORDER[a.category]!==CATEGORY_ORDER[b.category])return CATEGORY_ORDER[a.category]-CATEGORY_ORDER[b.category];
            if(SEVERITY_ORDER[a.severity]!==SEVERITY_ORDER[b.severity])return SEVERITY_ORDER[a.severity]-SEVERITY_ORDER[b.severity];
            if(PRIORITY_ORDER[a.priority]!==PRIORITY_ORDER[b.priority])return PRIORITY_ORDER[a.priority]-PRIORITY_ORDER[b.priority];
            return a.id.localeCompare(b.id);
        });

        return{
            schemaVersion:SCHEMA_VERSION,
            reportId:reportId,
            generatedAt:rawReport.analyzedAt||new Date().toISOString(),
            repository:rawReport.repository,
            summary:rawReport.summary||{},
            findings:{
                architecture:architecture.concat(layerViolations),
                security:security,
                deadCode:deadCode,
                duplicates:duplicates,
                layerViolations:layerViolations,
                all:allFindings
            },
            suggestions:suggestions,
            rawReport:rawReport
        };
    }

    function actionableIssues(normalized){
        if(!normalized||!normalized.findings)return[];
        return normalized.findings.all.map(function(f){
            return{
                id:f.id,
                category:f.category,
                subtype:f.subtype,
                severity:f.severity,
                priority:f.priority,
                title:f.title,
                description:f.description,
                targetFiles:f.targetFiles
            };
        });
    }

    function buildWorkflow(normalized){
        var issues=actionableIssues(normalized);
        var tasks=issues.map(function(issue,index){
            var baseCriteria=[
                'Update '+(issue.targetFiles[0]||'affected files')+' to resolve '+issue.title.toLowerCase()+'.',
                'Add or update tests that validate the fix.',
                'Ensure no regression in existing report metrics for this finding category.'
            ];
            return{
                id:stableId('task',[normalized.reportId,issue.id,index]),
                findingId:issue.id,
                order:index+1,
                category:issue.category,
                priority:issue.priority,
                severity:issue.severity,
                title:'Remediate: '+issue.title,
                targetFiles:issue.targetFiles,
                rationale:issue.description||'Automated remediation task generated from report findings.',
                acceptanceCriteria:baseCriteria,
                risk:issue.severity==='critical'||issue.severity==='high'?'high':(issue.severity==='medium'?'medium':'low'),
                dependsOn:[]
            };
        });
        var previousByCategory={};
        tasks.forEach(function(task){
            var prev=previousByCategory[task.category];
            if(prev)task.dependsOn.push(prev.id);
            previousByCategory[task.category]=task;
        });
        return{
            schemaVersion:SCHEMA_VERSION,
            reportId:normalized.reportId,
            repository:normalized.repository,
            generatedAt:new Date().toISOString(),
            strategy:['security','architecture','maintainability'],
            tasks:tasks
        };
    }

    function compactAgentView(normalized){
        return{
            schemaVersion:SCHEMA_VERSION,
            reportId:normalized.reportId,
            repository:normalized.repository,
            generatedAt:normalized.generatedAt,
            summary:{
                healthScore:normalized.summary.healthScore,
                healthGrade:normalized.summary.healthGrade,
                totalFindings:normalized.findings.all.length,
                securityFindings:normalized.findings.security.length,
                architectureFindings:normalized.findings.architecture.length,
                maintainabilityFindings:normalized.findings.deadCode.length+normalized.findings.duplicates.length
            },
            topFindings:normalized.findings.all.slice(0,25).map(function(f){
                return{id:f.id,category:f.category,severity:f.severity,priority:f.priority,title:f.title,targetFiles:f.targetFiles};
            }),
            suggestions:normalized.suggestions.slice(0,20)
        };
    }

    return{
        SCHEMA_VERSION:SCHEMA_VERSION,
        normalizeSeverity:normalizeSeverity,
        normalizePriority:normalizePriority,
        createRawReportFromUI:createRawReportFromUI,
        normalizeReport:normalizeReport,
        actionableIssues:actionableIssues,
        buildWorkflow:buildWorkflow,
        compactAgentView:compactAgentView
    };
}));
