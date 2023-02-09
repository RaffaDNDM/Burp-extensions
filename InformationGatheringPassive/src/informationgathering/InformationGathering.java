package informationgathering;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class InformationGathering implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("Custom Scanner checks");

        api.scanner().registerScanCheck(new CustomScanCheck(api));
    }
}