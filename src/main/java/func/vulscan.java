package func;

import UI.Tags;
import burp.*;
import utils.BurpAnalyzedRequest;
import yaml.YamlUtil;

import java.net.URL;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.Config.model;

public class vulscan {

    private IBurpExtenderCallbacks call;

    private BurpAnalyzedRequest Root_Request;

    private IExtensionHelpers help;
    public String Path_record;
    public BurpExtender burp;
    public IHttpService httpService;


    public vulscan(BurpExtender burp, BurpAnalyzedRequest Root_Request,byte[] request) {
        this.burp = burp;
        this.call = burp.call;
        this.help = burp.help;
        this.Root_Request = Root_Request;
        // 获取httpService对象
        if (request == null){
            request = this.Root_Request.requestResponse().getRequest();
        }
//        IRequestInfo iRequestInfo = help.analyzeRequest(request);
//        httpService = help.buildHttpService(iRequestInfo.getUrl().getHost(), iRequestInfo.getUrl().getPort(), iRequestInfo.getUrl().getProtocol());
        httpService = this.Root_Request.requestResponse().getHttpService();
        IRequestInfo analyze_Request = help.analyzeRequest(httpService, request);
        List<String> heads = analyze_Request.getHeaders();
        burp.ThreadPool = Executors.newFixedThreadPool((Integer) burp.Config_l.spinner1.getValue());


        // 判断请求方法为POST
        if (this.help.analyzeRequest(request).getMethod().equalsIgnoreCase("POST")) {
            // 将POST切换为GET请求
            request = this.help.toggleRequestMethod(request);
        }

        // 获取所有参数
        IRequestInfo iRequestInfo = this.help.analyzeRequest(request);
        List<IParameter> parameters = iRequestInfo.getParameters();

        // 判断参数列表不为空
        if (!parameters.isEmpty()) {
            for (IParameter parameter : parameters) {
                // 检查参数类型，避免删除不支持的类型（修复报错）
                if (parameter.getType() == IParameter.PARAM_URL || parameter.getType() == IParameter.PARAM_BODY) {
                    // 删除 URL 或 Body 参数
                    request = this.help.removeParameter(request, parameter);
                }
            }
        }

        // 创建新的请求类
//        IHttpRequestResponse newHttpRequestResponse = this.call.makeHttpRequest(httpService, request);
        IHttpRequestResponse newHttpRequestResponse = Root_Request.requestResponse();
        // 使用/分割路径
        IRequestInfo analyzeRequest = this.help.analyzeRequest(newHttpRequestResponse);
        List<String> headers = analyzeRequest.getHeaders();
        HashMap<String, String> headMap = vulscan.AnalysisHeaders(headers);
        String[] domainNames = vulscan.AnalysisHost(headMap.get("Host"));


        String[] paths = analyzeRequest.getUrl().getPath().split("\\?",2)[0].split("/");

        Map<String, Object> Yaml_Map = YamlUtil.readYaml(burp.Config_l.yaml_path);
        List<Map<String, Object>> Listx = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        if (paths.length == 0) {
            paths = new String[]{""};
        }
        List<String> Bypass_List = (List<String>) Yaml_Map.get("Bypass_List");
        //filter过滤路径
//        if(burp.Filter){
//            paths = getRemainingArray(paths);
//        }
        if (burp.DomainScan) {
            LaunchPath(true, domainNames, Listx, newHttpRequestResponse, heads, Bypass_List);
        }
        LaunchPath(false,paths,Listx,newHttpRequestResponse,heads,Bypass_List);



    }

    private void LaunchPath(Boolean ClearPath_record ,String[] paths,List<Map<String, Object>> Listx,IHttpRequestResponse newHttpRequestResponse,List<String> heads,List<String> Bypass_List){
        this.Path_record = "";
        for (String path : paths) {
            if (ClearPath_record){
                this.Path_record = "";
            }
            if (path.contains(".") && path.equals(paths[paths.length - 1])) {
                break;
            }
//            this.burp.call.printOutput(this.Path_record);

            if (!path.equals("")) {
                this.Path_record = this.Path_record + "/" + path;
            }
            //filter过滤优化，不删除，匹配跳过
            if (burp.Filter && isAnyStringInTable(path)){
                continue;
            }
            String url = this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getProtocol() + "://" + this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getHost() + ":" + this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getPort() + String.valueOf(this.Path_record);

            boolean is_InList;
            synchronized (this.burp.history_url) {
                is_InList = !this.burp.history_url.contains(url);
            }


            if (is_InList) {
                synchronized (this.burp.history_url) {
                    this.burp.history_url.add(url);
                }
                for (Map<String, Object> zidian : Listx) {
                    this.burp.ThreadPool.execute(new threads(zidian, this, newHttpRequestResponse, heads, Bypass_List));
                }


                int whileSiz = 0;
                while (true) {
//                    this.burp.call.printError(String.valueOf(whileSiz));
                    if (whileSiz >= 10){
                        this.burp.ThreadPool.shutdownNow();
                        this.burp.ThreadPool = Executors.newFixedThreadPool((Integer) this.burp.Config_l.spinner1.getValue());
                        this.burp.call.printError("Timeout: " + url + "/*");
                        break;
                    }
                    // 防止线程混乱，睡眠3.1秒
                    try {
                        Thread.sleep(3100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    if (((ThreadPoolExecutor) this.burp.ThreadPool).getActiveCount() == 0) {
                        break;
                    }
                    whileSiz += 1;

                }


            }else {
                this.burp.call.printError("Skip: " + url + "/*");
            }


        }
    }

    // 从表格中删除与字符串数组匹配的行，保留数组顺序
//    private static String[] getRemainingArray(String[] array) {
//        Set<String> tableDataSet = new HashSet<>();
//        int rowCount = model.getRowCount();
//
//        // 将表格中的所有值添加到 Set 中
//        for (int i = 0; i < rowCount; i++) {
//            String cellValue = (String) model.getValueAt(i, 0);
//            tableDataSet.add(cellValue);
//        }
//
//        // 使用 ArrayList 来存储未匹配的字符串，保留顺序
//        List<String> remainingList = new ArrayList<>();
//
//        // 遍历数组，保留不在表格中的元素
//        for (String s : array) {
//            if (!tableDataSet.contains(s)) {
//                remainingList.add(s);
//            }
//        }
//
//        // 将结果转换为数组并返回
//        return remainingList.toArray(new String[0]);
//    }

    //判断是否存在过滤列表中
    private static boolean isAnyStringInTable(String array) {
        Set<String> tableDataSet = new HashSet<>();
        int rowCount = model.getRowCount();
        // 将表格中的所有值添加到 Set 中
        for (int i = 0; i < rowCount; i++) {
            String cellValue = (String) model.getValueAt(i, 0);
            tableDataSet.add(cellValue);
        }
        // 遍历字符串数组，如果找到匹配的字符串，立即返回 true
        if (tableDataSet.contains(array)) {
            return true;
        }
        // 如果没有找到匹配项，返回 false
        return false;
    }

    public static void ir_add(Tags tag, String title, String method, String url, String StatusCode, String notes, String Size, IHttpRequestResponse newHttpRequestResponse) {
//        if (!tag.Get_URL_list().contains(url)) {
        tag.add(title, method, url, StatusCode, notes, Size, newHttpRequestResponse);
//        }
    }

    public static HashMap<String, String> AnalysisHeaders(List<String> headers){
        headers.remove(0);
        HashMap<String, String> headMap = new HashMap<String, String>();
        for (String i : headers){
            int indexLocation = i.indexOf(":");
            String key = i.substring(0,indexLocation).trim();
            String value = i.substring(indexLocation + 1).trim();
            headMap.put(key,value);
        }
        return headMap;

    }

    public static String[] AnalysisHost(String host){
        ArrayList<String> ExceptSubdomain = new ArrayList<String>(Collections.singletonList("www"));
        Pattern zhengze = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
        Matcher pipei = zhengze.matcher(host);
        if (!pipei.find()){
            List<String> hostArray = new ArrayList<>(Arrays.asList(host.split("\\.")));
            if (ExceptSubdomain.contains(hostArray.get(0))){
                hostArray.remove(0);
            }
            if (hostArray.get(hostArray.size() - 1).equals("cn") && hostArray.get(hostArray.size() - 2).equals("com")){
                hostArray.remove(hostArray.size() - 1);
                hostArray.remove(hostArray.size() - 1);
//                hostArray.remove(hostArray.size() - 2);
            }else {
                hostArray.remove(hostArray.size() - 1);
            }
            return hostArray.toArray(new String[0]);
        }
        return new String[]{};
    }


}

