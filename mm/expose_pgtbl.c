#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/sched/mm.h>
#include <linux/expose_pgtbl.h>

#define vadd_iter	0x1000
#define BUF_SIZE	4096

struct mm_struct *get_task_mm_expose(struct task_struct *task)
{
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_KTHREAD)
			mm = NULL;
		else
			mmget(mm);
	}
	task_unlock(task);
	return mm;
}


/*
 * Investigate the page table layout.
 *
 * The page table layout varies over different architectures (eg. x86 vs arm).
 * It also changes with the change of system configuration.
 *
 * You need to implement a system call to get the page table layout information
 * of the current system. Use syscall number 441.
 * @pgtbl_info : user address to store the related information; note the
 * normal page size can be inferred from the page_shift.
 */
SYSCALL_DEFINE1(get_pagetable_layout, struct pagetable_layout_info __user *, pgtbl_info)
{
	/*
	 * if(!pgtbl_info)
	 * 	return -EINVAL;
	 */
	struct pagetable_layout_info tmp;

	tmp.pgdir_shift = PGDIR_SHIFT;
	tmp.p4d_shift = P4D_SHIFT;
	tmp.pud_shift = PUD_SHIFT;
	tmp.pmd_shift = PMD_SHIFT;
	tmp.page_shift = PAGE_SHIFT;
	if (copy_to_user(pgtbl_info, &tmp, sizeof(struct pagetable_layout_info)))
		return -EFAULT;
	return 0;
}

/*
 * struct expose_pgtbl_args {
 *	unsigned long fake_pgd;
 *	unsigned long fake_p4ds;
 *	unsigned long fake_puds;
 *	unsigned long fake_pmds;
 *	unsigned long page_table_addr;
 *	unsigned long begin_vaddr;
 *	unsigned long end_vaddr;
 * };
 */

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct expose_pgtbl_args local_args;
	struct task_struct *from_task = current;
	struct mm_struct *from_mm;
	struct mm_struct *to_mm;
	struct vm_area_struct *to_vma;
	unsigned long map_from_addr, map_to_addr;
	pgprot_t flags;
	int result = 0;

	pgd_t *fake_pgd;
	p4d_t *fake_p4d;
	pud_t *fake_pud;
	pmd_t *fake_pmd;
	p4d_t *p4d_e;
	pud_t *pud_e;
	pmd_t *pmd_e;
	pte_t *pte_e;

	if (!args)
		return -EINVAL;
	if (copy_from_user(&local_args, args, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;

	if (pid != -1)
		from_task = find_task_by_vpid(pid);
	if (!from_task || !current)
		return -ESRCH;

	from_mm = get_task_mm_expose(from_task);
	if (!from_mm)
		return -ESRCH;

	to_mm = get_task_mm_expose(current);
	if (!to_mm)
		return -ESRCH;

	/* TODO: copy the page tables */
	fake_pgd->pgd = local_args.fake_pgd;
	fake_p4d->pgd.pgd = local_args.fake_p4ds;
	fake_pud->pud = local_args.fake_puds;
	fake_pmd->pmd = local_args.fake_pmds;
	map_to_addr = local_args.page_table_addr;

	p4d_e = p4d_alloc(to_mm, fake_pgd, map_to_addr);
	p4d_e->pgd.pgd = local_args.fake_p4ds;
	pud_e = pud_alloc(to_mm, p4d_e, map_to_addr);
	pud_e->pud = local_args.fake_puds;
	pmd_e = pmd_alloc(to_mm, pud_e, map_to_addr);
	pmd_e->pmd = local_args.fake_pmds;
	pte_e = pte_alloc_map(to_mm, pmd_e, map_to_addr);
	pte_e->pte = map_to_addr;

	/* do the mapping from the VMA to page_table_addr*/
	map_from_addr = local_args.begin_vaddr;

	to_vma = find_vma(to_mm, local_args.page_table_addr);
	flags = to_vma->vm_page_prot;

	while (PAGE_ALIGN(map_from_addr) < PAGE_ALIGN(local_args.end_vaddr)) {
		/* walk the tables to get the physical PFN to map from */
		/* TODO: should we use the fake tables for this? */
		unsigned long map_pfn;
		pgd_t *map_pgd = pgd_offset(from_mm, map_from_addr);
		p4d_t *map_p4d = p4d_offset(map_pgd, map_from_addr);
		pud_t *map_pud = pud_offset(map_p4d, map_from_addr);
		pmd_t *map_pmd = pmd_offset(map_pud, map_from_addr);

		#ifdef CONFIG_ARM64
		map_pfn = (pmd_val(READ_ONCE(*map_pmd)) & ((1UL << 48) - 1)) >> PAGE_SHIFT;
		#else
		map_pfn = pmd_pfn(READ_ONCE(*map_pmd));
		#endif

		result = remap_pfn_range(to_vma, map_to_addr,
					 map_pfn, PAGE_SIZE, flags);
		if (result != 0)
			return result;

		map_from_addr = PAGE_ALIGN(map_from_addr + PAGE_SIZE);
		map_to_addr = PAGE_ALIGN(map_to_addr + PAGE_SIZE);
		to_vma = find_vma(to_mm, map_to_addr);
	}

	return 0;
}

SYSCALL_DEFINE1(get_pa_contents, long, phys_addr)
{
	/* This may need to be tested and revised after 442 is done for further testing */
	return *((int *)__va(phys_addr));
}
