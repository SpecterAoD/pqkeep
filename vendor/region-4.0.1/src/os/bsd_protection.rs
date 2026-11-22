impl Protection {
  fn from_native(protection: c_int) -> Self {
    const MAPPINGS: &[(c_int, Protection)] = &[
      (KVME_PROT_READ, Protection::READ),
      (KVME_PROT_WRITE, Protection::WRITE),
      (KVME_PROT_EXEC, Protection::EXECUTE),
    ];

    MAPPINGS
      .iter()
      .filter(|(flag, _)| protection & *flag == *flag)
      .fold(Protection::NONE, |acc, (_, prot)| acc | *prot)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn protection_flags_are_mapped_from_native() {
    let rw = KVME_PROT_READ | KVME_PROT_WRITE;
    let rwx = rw | KVME_PROT_EXEC;

    assert_eq!(Protection::from_native(0), Protection::NONE);
    assert_eq!(Protection::from_native(KVME_PROT_READ), Protection::READ);
    assert_eq!(Protection::from_native(rw), Protection::READ_WRITE);
    assert_eq!(Protection::from_native(rwx), Protection::READ_WRITE_EXECUTE);
  }
}
