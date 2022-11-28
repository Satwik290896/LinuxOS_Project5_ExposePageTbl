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
	 *	return -EINVAL;
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
	struct task_struct *to_task = current;
	struct task_struct *from_task;
	struct mm_struct *to_mm;
	struct mm_struct *from_mm;
	struct vm_area_struct *from_vma;
	struct vm_area_struct *to_vma;
	unsigned long map_from_addr, map_to_addr, map_begin_addr, map_end_addr, begin_page_table;
	pgprot_t flags;
	int result = 0;

	unsigned long map_pfn;
	unsigned long num_pmds, num_puds, num_pgds, tot_num_pages, num_pages_rem;

	if (!args)
		return -EINVAL;
	if (copy_from_user(&local_args, args, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;
		
	
	if (pid != -1)
		from_task = find_task_by_vpid(pid);
	else
		from_task = current;

	if (!from_task || !current)
		return -ESRCH;

	from_mm = get_task_mm_expose(from_task);
	if (!from_mm)
		return -ESRCH;

	to_mm = get_task_mm_expose(to_task);
	if (!to_mm)
		return -ESRCH;



	map_begin_addr = local_args.begin_vaddr;
	map_end_addr = local_args.end_vaddr;
	begin_page_table = local_args.page_table_addr;
	
	tot_num_pages = (map_end_addr >> PAGE_SHIFT) - (map_begin_addr>>PAGE_SHIFT) + 1;
	num_pmds = (map_end_addr >> PMD_SHIFT) - (map_begin_addr>>PMD_SHIFT) + 1;
	num_puds = (map_end_addr >> PUD_SHIFT) - (map_begin_addr>>PUD_SHIFT) + 1;
	num_pgds = 1;

	to_vma = find_vma(to_mm, begin_page_table);
	flags = to_vma->vm_page_prot;

	
	
	
	map_from_addr = map_begin_addr;
	
	
	for (int j = 0; j < num_puds; j++) {
		for (int i = 0; i < num_pmds; i++) {

			map_to_addr = begin_page_table;
			/*Loop starts from here?*/
		
			/*Find map_pfn using pmd_pfn() of the "map_from_addr"*/
			pgd_t *map_pgd = pgd_offset(from_mm, map_from_addr);
			p4d_t *map_p4d = p4d_offset(map_pgd, map_from_addr);
			pud_t *map_pud = pud_offset(map_p4d, map_from_addr);
			pmd_t *map_pmd = pmd_offset(map_pud, map_from_addr);
			map_pfn = pmd_pfn(READ_ONCE(*map_pmd));
	
			/*remap_pfn_range()*/
			result = remap_pfn_range(to_vma, map_to_addr, map_pfn, PAGE_SIZE, flags);
			if (!result)
				return result;
		

			/*Updates at the End of the Loop*/
			map_to_addr +=  PAGE_SIZE;
			map_from_addr = ((map_from_addr >> PAGE_SHIFT) + 512) << PAGE_SHIFT;
		
			/*Loop Ends here. Iterate with the above Changed behaviours*/
	
		}
	}
	
	unsigned long copy_pmd = local_args.fake_pmds + pmd_index(map_begin_addr);`
	
	if (copy_to_user(&args->fake_pmds, &copy_pmd, sizeof(unsigned long)))
		return -EINVAL;
			
	unsigned long copy_pud = local_args.fake_puds + pud_index(map_begin_addr);`
	
	if (copy_to_user(&args->fake_puds, &copy_pud, sizeof(unsigned long)))
		return -EINVAL;
		
	unsigned long copy_pgd = local_args.fake_pgd + pgd_index(map_begin_addr);`
	
	if (copy_to_user(&args->fake_pgd, &copy_pgd, sizeof(unsigned long)))
		return -EINVAL;
		
		

	return 0;
}

SYSCALL_DEFINE1(get_pa_contents, long, phys_addr)
{
	/* This may need to be tested and revised after 442 is done for further testing */
	return *((char *)__va(phys_addr));
}
