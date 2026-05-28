use core::cmp::Ordering;

pub fn select_positive_credit_top_k_mask(
    credits: &[f64],
    schema_dim: usize,
    top_k: usize,
) -> Result<Option<Vec<bool>>, String> {
    if credits.len() != schema_dim {
        return Err(format!(
            "BOFuzz auto-credit error: credits length {} != schema_dim {}",
            credits.len(),
            schema_dim
        ));
    }
    if top_k == 0 || top_k > schema_dim {
        return Err(format!(
            "BOFuzz auto-credit error: credit_top_k {} outside valid range 1..={}",
            top_k, schema_dim
        ));
    }

    let mut positive = Vec::new();
    for (idx, &credit) in credits.iter().enumerate() {
        if !credit.is_finite() {
            return Err(format!(
                "BOFuzz auto-credit error: non-finite credit at schema index {}",
                idx
            ));
        }
        if credit < 0.0 {
            return Err(format!(
                "BOFuzz auto-credit error: negative credit at schema index {}",
                idx
            ));
        }
        if credit > 0.0 {
            positive.push((idx, credit));
        }
    }

    if positive.is_empty() {
        return Ok(None);
    }

    positive.sort_by(|(a_idx, a_credit), (b_idx, b_credit)| {
        b_credit
            .partial_cmp(a_credit)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a_idx.cmp(b_idx))
    });

    let mut mask = vec![false; schema_dim];
    for (idx, _) in positive.into_iter().take(top_k) {
        mask[idx] = true;
    }
    Ok(Some(mask))
}

pub fn project_vector_by_mask<T: Clone>(full: &[T], mask: &[bool]) -> Result<Vec<T>, String> {
    if full.len() != mask.len() {
        return Err(format!(
            "BOFuzz mask projection error: vector length {} != mask length {}",
            full.len(),
            mask.len()
        ));
    }
    Ok(full
        .iter()
        .zip(mask.iter())
        .filter(|(_, enabled)| **enabled)
        .map(|(value, _)| value.clone())
        .collect())
}

pub fn mask_to_bitstring(mask: &[bool]) -> String {
    mask.iter().map(|&v| if v { '1' } else { '0' }).collect()
}

pub fn equal_simplex(dim: usize) -> Vec<f64> {
    if dim == 0 {
        return Vec::new();
    }
    vec![1.0 / dim as f64; dim]
}

pub fn normalize_credit_or_equal_simplex(credits: &[f64]) -> Result<(Vec<f64>, bool, f64), String> {
    if credits.is_empty() {
        return Ok((Vec::new(), false, 0.0));
    }
    let mut positive_sum = 0.0;
    for (idx, &credit) in credits.iter().enumerate() {
        if !credit.is_finite() {
            return Err(format!(
                "BOFuzz credit normalization error: non-finite credit at index {}",
                idx
            ));
        }
        if credit < 0.0 {
            return Err(format!(
                "BOFuzz credit normalization error: negative credit at index {}",
                idx
            ));
        }
        if credit > 0.0 {
            positive_sum += credit;
        }
    }
    if positive_sum > 0.0 {
        Ok((
            credits.iter().map(|v| *v / positive_sum).collect(),
            true,
            positive_sum,
        ))
    } else {
        Ok((equal_simplex(credits.len()), false, 0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_credit_selects_positive_features_only() {
        let mask = select_positive_credit_top_k_mask(&[0.0, 10.0, 0.0, 1.0], 4, 4)
            .unwrap()
            .unwrap();
        assert_eq!(mask, vec![false, true, false, true]);
    }

    #[test]
    fn auto_credit_selects_at_most_top_k_positive_features() {
        let mask = select_positive_credit_top_k_mask(&[1.0, 5.0, 3.0, 2.0], 4, 2)
            .unwrap()
            .unwrap();
        assert_eq!(mask, vec![false, true, true, false]);
    }

    #[test]
    fn auto_credit_selects_fewer_than_k_when_only_fewer_positive_exist() {
        let mask = select_positive_credit_top_k_mask(&[0.0, 10.0, 0.0, 0.0], 4, 4)
            .unwrap()
            .unwrap();
        assert_eq!(mask, vec![false, true, false, false]);
    }

    #[test]
    fn auto_credit_returns_none_when_all_credits_are_zero() {
        assert!(
            select_positive_credit_top_k_mask(&[0.0, 0.0, 0.0, 0.0], 4, 4)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn auto_credit_ties_break_by_schema_index() {
        let mask = select_positive_credit_top_k_mask(&[0.0, 10.0, 5.0, 5.0], 4, 2)
            .unwrap()
            .unwrap();
        assert_eq!(mask, vec![false, true, true, false]);
    }

    #[test]
    fn negative_credits_are_rejected() {
        assert!(select_positive_credit_top_k_mask(&[1.0, -1.0], 2, 1).is_err());
    }

    #[test]
    fn non_finite_credits_are_rejected() {
        assert!(select_positive_credit_top_k_mask(&[1.0, f64::NAN], 2, 1).is_err());
    }

    #[test]
    fn projection_preserves_schema_order() {
        let projected =
            project_vector_by_mask(&[10, 20, 30, 40], &[false, true, true, false]).unwrap();
        assert_eq!(projected, vec![20, 30]);
    }

    #[test]
    fn credit_normalization_is_exact_when_signal_exists() {
        let (v, positive, sum) = normalize_credit_or_equal_simplex(&[2.0, 1.0, 1.0]).unwrap();
        assert!(positive);
        assert_eq!(sum, 4.0);
        assert_eq!(v, vec![0.5, 0.25, 0.25]);
    }
}
