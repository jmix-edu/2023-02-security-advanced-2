package com.company.samplesales.security.keycloak;

import io.jmix.oidc.claimsmapper.BaseClaimsRolesMapper;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.security.role.RowLevelRoleRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.*;

@Component("sales_AppClaimsROlesMapper")
public class AppClaimsRolesMapper extends BaseClaimsRolesMapper {

    public AppClaimsRolesMapper(ResourceRoleRepository resourceRoleRepository, RowLevelRoleRepository rowLevelRoleRepository) {
        super(resourceRoleRepository, rowLevelRoleRepository);
    }

    @Override
    public Collection<? extends GrantedAuthority> toGrantedAuthorities(Map<String, Object> claims) {
        return super.toGrantedAuthorities(claims);
    }

    @Override
    protected Collection<String> getResourceRolesCodes(Map<String, Object> claims) {
        return getCodesFrom(claims, "jmix_resource");
    }

    @Override
    protected Collection<String> getRowLevelRoleCodes(Map<String, Object> claims) {
        return getCodesFrom(claims, "jmix_row_level");
    }

    protected Collection<String> getCodesFrom(Map<String, Object> claims, String prefix) {
        Object claimRoles = claims.get("kk_roles");
        if (claimRoles instanceof Collection) {
            Collection<String> roles = (Collection<String>) claimRoles;

            List<String> resultRoles = new ArrayList<>();
            for (String role : roles) {
                if (!role.startsWith(prefix)) {
                    continue;
                }
                String code = role.split("\\$")[1];
                resultRoles.add(code);
            }
            return resultRoles;
        }
        return Collections.emptySet();
    }
}
