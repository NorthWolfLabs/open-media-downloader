CREATE INDEX acquisition_source_lookup ON jobs(json_extract(plan_json,'$.release.reference.provider'),json_extract(plan_json,'$.release.reference.id'),state,history_removed);
